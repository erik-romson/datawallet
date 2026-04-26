package com.erikromson.datawallet.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.erikromson.datawallet.crypto.UuidV7;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.File;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;

/// Encrypts a plaintext payload for a verifier (looked up by handle in Postgres),
/// signs the envelope with the dev issuer key, and POSTs it to /v1/entries.
///
/// Requires `init-dev-trust` to have been run first (reads issuer.json from
/// `--state-dir`). For dev mode the server must be running with profile `it` and
/// `datawallet.security.issuer-mtls=false` so it accepts the X-Test-Issuer-Id
/// header in lieu of mTLS.
@Component
@Profile("cli")
@Command(
        name = "share-with-verifier",
        description = "Encrypt + sign + upload an envelope for a registered verifier",
        mixinStandardHelpOptions = true
)
public class ShareWithVerifierCommand implements Callable<Integer> {

    @Option(names = "--url", defaultValue = "http://localhost:8443",
            description = "Server URL (default: ${DEFAULT-VALUE})")
    String url;

    @Option(names = "--to", required = true, description = "Verifier handle")
    String handle;

    @Option(names = "--plaintext", description = "Plaintext content (use --plaintext-file for file input)")
    String plaintext;

    @Option(names = "--plaintext-file", description = "Plaintext content from file")
    File plaintextFile;

    @Option(names = "--description", description = "Server-visible description")
    String description = "";

    @Option(names = "--state-dir", description = "Where init-dev-trust wrote issuer.json")
    File stateDir = new File(System.getProperty("user.home"), ".datawallet/dev");

    @Option(names = "--jdbc-url",
            defaultValue = "jdbc:postgresql://localhost:5432/datawallet",
            description = "JDBC URL for verifier lookup (default: ${DEFAULT-VALUE})")
    String jdbcUrl;

    @Option(names = "--jdbc-user", defaultValue = "wallet_app",
            description = "DB user (default: ${DEFAULT-VALUE})")
    String jdbcUser;

    @Option(names = "--jdbc-password", defaultValue = "devpw",
            description = "DB password (default: ${DEFAULT-VALUE} for dev)",
            interactive = true, arity = "0..1")
    char[] jdbcPassword;

    @Option(names = "--passphrase", defaultValue = "devpassphrase",
            description = "Passphrase for issuer key (default: ${DEFAULT-VALUE} for dev)",
            interactive = true, arity = "0..1")
    char[] passphrase;

    @Option(names = "--dev", defaultValue = "true",
            description = "Dev mode: send X-Test-Issuer-Id instead of mTLS (default: ${DEFAULT-VALUE}; pass --dev=false for production mTLS)",
            arity = "0..1", fallbackValue = "true")
    boolean dev;

    @Override
    public Integer call() throws Exception {
        if ((plaintext == null) == (plaintextFile == null)) {
            System.err.println("Provide exactly one of --plaintext or --plaintext-file");
            return 2;
        }
        String plaintextContent = plaintext != null
                ? plaintext
                : Files.readString(plaintextFile.toPath());

        // 1. Load issuer state
        File issuerJsonFile = new File(stateDir, "issuer.json");
        if (!issuerJsonFile.exists()) {
            System.err.println("issuer.json not found at " + issuerJsonFile.getAbsolutePath());
            System.err.println("Run init-dev-trust first.");
            return 1;
        }
        ObjectMapper json = new ObjectMapper();
        JsonNode meta = json.readTree(issuerJsonFile);
        UUID issuerId = UUID.fromString(meta.get("issuer_id").asText());
        String issuerLabel = meta.get("issuer_label").asText();
        byte[] issuerKeyId = HexFormat.of().parseHex(meta.get("issuer_key_id_hex").asText());
        File issuerKeyFile = new File(meta.get("issuer_priv_path").asText());

        // 2. Look up verifier in DB
        UUID verifierId;
        byte[] verifierEncPubKey;
        byte[] verifierEncKeyId;
        try (Connection conn = DriverManager.getConnection(jdbcUrl, jdbcUser, new String(jdbcPassword))) {
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT verifier_id, enc_public_key, enc_key_id FROM verifiers WHERE handle = ?")) {
                ps.setString(1, handle);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) {
                        System.err.println("No verifier found with handle: " + handle);
                        return 1;
                    }
                    verifierId = (UUID) rs.getObject("verifier_id");
                    verifierEncPubKey = rs.getBytes("enc_public_key");
                    verifierEncKeyId = rs.getBytes("enc_key_id");
                }
            }
        }
        java.util.Arrays.fill(jdbcPassword, '\0');

        System.out.println("Found verifier " + handle + " (id=" + verifierId + ")");

        // 3. Load issuer private key
        byte[] issuerPrivKey = CliKeyStore.load(issuerKeyFile.toPath(), passphrase);
        java.util.Arrays.fill(passphrase, '\0');

        // 4. Build envelope (reuses BuildEnvelopeCommand.buildEnvelope)
        UUID entryId = UuidV7.now();
        long createdAt = System.currentTimeMillis();
        List<BuildEnvelopeCommand.RecipientInfo> recipients = List.of(
                new BuildEnvelopeCommand.RecipientInfo(verifierId, verifierEncKeyId, verifierEncPubKey)
        );
        byte[] envelopeBytes = BuildEnvelopeCommand.buildEnvelope(
                plaintextContent, entryId, issuerId, issuerLabel, issuerKeyId,
                issuerPrivKey, createdAt, description, recipients
        );
        java.util.Arrays.fill(issuerPrivKey, (byte) 0);

        // 5. POST to /v1/entries
        HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url + "/v1/entries"))
                .header("Content-Type", "application/cbor")
                .POST(HttpRequest.BodyPublishers.ofByteArray(envelopeBytes));
        if (dev) {
            reqBuilder.header("X-Test-Issuer-Id", issuerId.toString());
        }
        HttpClient client = HttpClient.newHttpClient();
        HttpResponse<String> resp = client.send(reqBuilder.build(),
                HttpResponse.BodyHandlers.ofString());

        System.out.println("POST " + url + "/v1/entries");
        System.out.println("Status: " + resp.statusCode());
        System.out.println(resp.body());

        if (resp.statusCode() != 200 && resp.statusCode() != 201) {
            return 1;
        }
        System.out.println();
        System.out.println("Shared entry " + entryId + " with " + handle + ".");
        return 0;
    }
}
