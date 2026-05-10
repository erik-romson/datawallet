package com.erikromson.datawallet.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.erikromson.datawallet.crypto.Ed25519;
import com.erikromson.datawallet.crypto.UuidV7;
import com.erikromson.datawallet.directory.DirectoryRecord;
import com.erikromson.datawallet.directory.DirectoryRecordCodec;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.File;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;

/// Encrypts plaintext for a verifier and posts it to the server.
///
/// Reads the install keypair from state dir, computes a PoP signature,
/// mints a bearer JWT via the intermediate service, looks up the verifier's
/// encryption key, builds and signs a CBOR envelope, then POSTs it to the
/// server. The bearer JWT is never written to disk.
@Component
@Profile("cli")
@Command(
        name = "share",
        description = "Encrypt plaintext for a verifier and post it to the server",
        mixinStandardHelpOptions = true
)
public class ShareCommand implements Callable<Integer> {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();
    private static final byte[] POP_MESSAGE = "datawallet-token-pop".getBytes(StandardCharsets.US_ASCII);

    @Option(names = "--server-url", required = true,
            description = "Wallet server base URL")
    String serverUrl;

    @Option(names = "--intermediate-url", required = true,
            description = "Intermediate service base URL")
    String intermediateUrl;

    @Option(names = "--state-dir", required = true,
            description = "Directory containing install keys and signed record")
    File stateDir;

    @Option(names = "--passphrase", defaultValue = "devpassphrase",
            description = "Passphrase for decrypting the install private key (default: ${DEFAULT-VALUE})",
            interactive = true, arity = "0..1")
    char[] passphrase;

    @Option(names = "--to", required = true,
            description = "Verifier handle to share with")
    String verifierHandle;

    @Option(names = "--plaintext", required = true,
            description = "Plaintext to encrypt and share")
    String plaintext;

    @Option(names = "--description",
            description = "Entry description")
    String description = "";

    @Override
    public Integer call() throws Exception {
        Path stateDirPath = stateDir.toPath();
        byte[] installPrivKey = CliKeyStore.load(stateDirPath.resolve("install.privkey.box"), passphrase);
        byte[] signedRecordBytes = Files.readAllBytes(stateDirPath.resolve("install.signed_record.cbor"));

        DirectoryRecordCodec dirCodec = new DirectoryRecordCodec();
        DirectoryRecord installRecord = dirCodec.decode(signedRecordBytes);
        UUID installUuid = bytesToUuid(installRecord.subjectId());
        byte[] installKeyId = installRecord.keyId();

        byte[] popSignature = Ed25519.signDetached(installPrivKey, POP_MESSAGE);

        ObjectMapper json = new ObjectMapper();
        HttpClient client = HttpClient.newHttpClient();

        // Mint bearer via intermediate
        Map<String, Object> tokenBody = new LinkedHashMap<>();
        tokenBody.put("signed_directory_record", B64URL.encodeToString(signedRecordBytes));
        tokenBody.put("pop_signature", B64URL.encodeToString(popSignature));
        tokenBody.put("attestation_token", "stub");

        HttpResponse<String> tokenResp = client.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(intermediateUrl + "/token"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(tokenBody)))
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        if (tokenResp.statusCode() != 200) {
            System.err.println("Token mint failed: HTTP " + tokenResp.statusCode() + " " + tokenResp.body());
            return 1;
        }
        String bearer = json.readTree(tokenResp.body()).get("bearer").asText();

        // Resolve verifier's encryption public key
        HttpResponse<String> loginBlobResp = client.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(serverUrl + "/v1/verifiers/" + verifierHandle + "/login-blob"))
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());

        if (loginBlobResp.statusCode() != 200) {
            System.err.println("Verifier lookup failed: HTTP " + loginBlobResp.statusCode());
            return 1;
        }

        JsonNode loginBlob = json.readTree(loginBlobResp.body());
        UUID verifierId = UUID.fromString(loginBlob.get("verifier_id").asText());
        byte[] verifierEncPubKey = B64URL_DEC.decode(loginBlob.get("enc_public_key").asText());
        byte[] verifierEncKeyId = B64URL_DEC.decode(loginBlob.get("enc_key_id").asText());

        // Build and sign CBOR envelope
        UUID entryId = UuidV7.now();
        long createdAt = System.currentTimeMillis();

        byte[] envelopeBytes = BuildEnvelopeCommand.buildEnvelope(
                plaintext, entryId, installUuid, installUuid.toString(),
                installKeyId, installPrivKey, createdAt, description,
                List.of(new BuildEnvelopeCommand.RecipientInfo(verifierId, verifierEncKeyId, verifierEncPubKey))
        );

        // POST envelope with bearer token
        HttpResponse<String> entriesResp = client.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(serverUrl + "/v1/entries"))
                        .header("Content-Type", "application/cbor")
                        .header("Authorization", "Bearer " + bearer)
                        .POST(HttpRequest.BodyPublishers.ofByteArray(envelopeBytes))
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        if (entriesResp.statusCode() != 201) {
            System.err.println("Entry creation failed: HTTP " + entriesResp.statusCode()
                    + " " + entriesResp.body());
            return 1;
        }

        System.out.println(json.readTree(entriesResp.body()).get("entry_id").asText());
        return 0;
    }

    private static UUID bytesToUuid(byte[] bytes) {
        ByteBuffer buf = ByteBuffer.wrap(bytes);
        return new UUID(buf.getLong(), buf.getLong());
    }
}
