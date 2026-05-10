package com.erikromson.datawallet.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.erikromson.datawallet.crypto.Ed25519;
import com.erikromson.datawallet.crypto.Random;
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
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;

/// Enrolls a new mobile install against the intermediate signing service.
///
/// Generates a fresh Ed25519 keypair, POSTs to `POST /enroll`, and persists
/// `install.privkey.box` and `install.signed_record.cbor` to the state dir
/// on success. No files are written if the HTTP call fails (no half-state).
@Component
@Profile("cli")
@Command(
        name = "enroll",
        description = "Enroll a mobile install against the intermediate signing service",
        mixinStandardHelpOptions = true
)
public class EnrollCommand implements Callable<Integer> {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();

    @Option(names = "--intermediate-url", required = true,
            description = "Base URL of the intermediate service")
    String intermediateUrl;

    @Option(names = "--install-uuid",
            description = "Install UUID (default: random UUIDv7)")
    String installUuidStr;

    @Option(names = "--state-dir", required = true,
            description = "Directory to persist install keys and signed record")
    File stateDir;

    @Option(names = "--passphrase", defaultValue = "devpassphrase",
            description = "Passphrase for encrypting the install private key (default: ${DEFAULT-VALUE})",
            interactive = true, arity = "0..1")
    char[] passphrase;

    @Override
    public Integer call() throws Exception {
        UUID installUuid = installUuidStr != null ? UUID.fromString(installUuidStr) : UuidV7.now();

        byte[] seed = Random.bytes(32);
        Ed25519.KeyPair kp = Ed25519.seedKeypair(seed);

        ObjectMapper json = new ObjectMapper();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("install_uuid", installUuid.toString());
        body.put("pubkey", B64URL.encodeToString(kp.publicKey()));
        body.put("attestation_token", "stub");

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(intermediateUrl + "/enroll"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(body)))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            System.err.println("Enroll failed: HTTP " + response.statusCode() + " " + response.body());
            return 1;
        }

        JsonNode resp = json.readTree(response.body());
        byte[] signedRecord = B64URL_DEC.decode(resp.get("signed_record").asText());

        Path stateDirPath = stateDir.toPath();
        Files.createDirectories(stateDirPath);
        CliKeyStore.save(stateDirPath.resolve("install.privkey.box"), kp.privateKey(), passphrase);
        Files.write(stateDirPath.resolve("install.signed_record.cbor"), signedRecord);

        System.out.println(installUuid);
        return 0;
    }
}
