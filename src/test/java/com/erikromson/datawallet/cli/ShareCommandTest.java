package com.erikromson.datawallet.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.erikromson.datawallet.crypto.Ed25519;
import com.erikromson.datawallet.crypto.Random;
import com.erikromson.datawallet.crypto.Sha256;
import com.erikromson.datawallet.crypto.UuidV7;
import com.erikromson.datawallet.crypto.X25519;
import com.erikromson.datawallet.directory.DirectoryRecord;
import com.erikromson.datawallet.directory.DirectoryRecordCodec;
import com.erikromson.datawallet.directory.PinnedRoot;
import com.erikromson.datawallet.directory.PinnedRootHolder;
import com.erikromson.datawallet.directory.RootSignature;
import com.erikromson.datawallet.directory.RootUpdateCodec;
import com.erikromson.datawallet.domain.DirectoryRecordEntity;
import com.erikromson.datawallet.domain.DirectoryRecordRepository;
import com.erikromson.datawallet.persistence.PostgresTestcontainer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "datawallet.security.issuer-mtls=false",
                "datawallet.security.issuer-bearer.enabled=true",
                "datawallet.security.issuer-bearer.audience=urn:datawallet:server"
        }
)
@ActiveProfiles("test")
@Import(PostgresTestcontainer.class)
class ShareCommandTest {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final ObjectMapper JSON = new ObjectMapper();

    @Value("${local.server.port}")
    int serverPort;

    @Autowired
    JdbcTemplate jdbcTemplate;

    @Autowired
    DirectoryRecordRepository directoryRecordRepository;

    @Autowired
    PinnedRootHolder pinnedRootHolder;

    @TempDir
    Path stateDir;

    // Per-test state
    Ed25519.KeyPair intKp;
    byte[] intKeyId;
    Ed25519.KeyPair installKp;
    UUID installUuid;
    byte[] installKeyId;
    String verifierHandle;
    UUID verifierId;
    X25519.KeyPair aliceEncKp;
    byte[] aliceEncKeyId;

    HttpServer mockIntermediate;
    int mockIntermediatePort;
    volatile HttpHandler tokenHandler;

    @BeforeEach
    void setup() throws Exception {
        // Start mock intermediate with a delegating /token handler
        mockIntermediate = HttpServer.create(new InetSocketAddress(0), 0);
        mockIntermediatePort = mockIntermediate.getAddress().getPort();
        mockIntermediate.createContext("/token", exchange -> tokenHandler.handle(exchange));
        mockIntermediate.start();

        // Clean test-owned rows (entries first due to FK, then directory/root)
        jdbcTemplate.update("DELETE FROM entry_recipients");
        jdbcTemplate.update("DELETE FROM entries");
        jdbcTemplate.update("DELETE FROM directory_records WHERE record_type IN ('intermediate', 'issuer')");
        jdbcTemplate.update("DELETE FROM pinned_root_history");

        // Build trust chain from scratch so tests are fully self-contained
        long now = System.currentTimeMillis();
        long validFrom = now - 60_000;
        long validUntil = now + 365L * 24 * 3600 * 1000;

        // Root quorum (1-of-1)
        byte[] rootSeed = Random.bytes(32);
        Ed25519.KeyPair rootKp = Ed25519.seedKeypair(rootSeed);
        byte[] rootKeyId = Random.bytes(16);
        PinnedRoot testRoot = new PinnedRoot(
                1, "ed25519", 1,
                List.of(new PinnedRoot.RootEntry(rootKeyId, rootKp.publicKey(), validFrom, validUntil))
        );
        byte[] pinnedRootCbor = new RootUpdateCodec().encodePinnedRoot(testRoot);
        jdbcTemplate.update("INSERT INTO pinned_root_history (pinned_root_cbor) VALUES (?)", pinnedRootCbor);
        // Make the in-memory holder aware of the test root immediately
        pinnedRootHolder.update(testRoot);

        // Intermediate keypair + root-signed directory record
        byte[] intSeed = Random.bytes(32);
        intKp = Ed25519.seedKeypair(intSeed);
        intKeyId = Random.bytes(16);
        UUID intUuid = UuidV7.now();

        DirectoryRecordCodec dirCodec = new DirectoryRecordCodec();
        DirectoryRecord intUnsigned = new DirectoryRecord(
                1, "intermediate", uuidToBytes(intUuid), intKeyId,
                intKp.publicKey(), "sign", "active",
                validFrom, validUntil, now, List.of(), null, null
        );
        byte[] intSignedBytes = dirCodec.signedBytesOf(intUnsigned);
        byte[] intRootSig = Ed25519.signDetached(rootKp.privateKey(), intSignedBytes);
        DirectoryRecord intSigned = new DirectoryRecord(
                1, "intermediate", uuidToBytes(intUuid), intKeyId,
                intKp.publicKey(), "sign", "active",
                validFrom, validUntil, now,
                List.of(new RootSignature(rootKeyId, intRootSig)), null, null
        );
        byte[] intRecordBytes = dirCodec.encode(intSigned);

        directoryRecordRepository.save(new DirectoryRecordEntity(
                "intermediate", intUuid, intKeyId, "active",
                Instant.ofEpochMilli(validFrom), Instant.ofEpochMilli(validUntil),
                Instant.ofEpochMilli(now), rootKeyId, null, intRecordBytes
        ));

        // Install keypair + intermediate-signed directory record
        installKp = Ed25519.seedKeypair(Random.bytes(32));
        installKeyId = Random.bytes(16);
        installUuid = UuidV7.now();

        DirectoryRecord installUnsigned = new DirectoryRecord(
                1, "issuer", uuidToBytes(installUuid), installKeyId,
                installKp.publicKey(), "sign", "active",
                validFrom, validUntil, now, List.of(), intKeyId, null
        );
        byte[] installSignedBytes = dirCodec.signedBytesOf(installUnsigned);
        byte[] installParentSig = Ed25519.signDetached(intKp.privateKey(), installSignedBytes);
        DirectoryRecord installSigned = new DirectoryRecord(
                1, "issuer", uuidToBytes(installUuid), installKeyId,
                installKp.publicKey(), "sign", "active",
                validFrom, validUntil, now, List.of(), intKeyId, installParentSig
        );
        byte[] installRecordBytes = dirCodec.encode(installSigned);

        directoryRecordRepository.save(new DirectoryRecordEntity(
                "issuer", installUuid, installKeyId, "active",
                Instant.ofEpochMilli(validFrom), Instant.ofEpochMilli(validUntil),
                Instant.ofEpochMilli(now), null, intKeyId, installRecordBytes
        ));

        // Write install state files (fast KDF params — load will use the stored params)
        CliKeyStore.save(stateDir.resolve("install.privkey.box"),
                installKp.privateKey(), "testpass".toCharArray(),
                256 * 1024L, 1L, 1);
        Files.write(stateDir.resolve("install.signed_record.cbor"), installRecordBytes);

        // Register a verifier via the real server endpoint
        aliceEncKp = X25519.seedKeypair(Random.bytes(32));
        aliceEncKeyId = Random.bytes(16);
        Ed25519.KeyPair aliceAuthKp = Ed25519.seedKeypair(Random.bytes(32));
        byte[] aliceAuthKeyId = Random.bytes(16);
        verifierHandle = "tv" + (System.nanoTime() % 1_000_000);

        Map<String, Object> kdfParams = new LinkedHashMap<>();
        kdfParams.put("alg", "argon2id");
        kdfParams.put("m", 268_435_456L);
        kdfParams.put("t", 3);
        kdfParams.put("p", 1);
        kdfParams.put("version", 19);

        Map<String, Object> regBody = new LinkedHashMap<>();
        regBody.put("handle", verifierHandle);
        regBody.put("display_name", verifierHandle);
        regBody.put("enc_public_key", B64URL.encodeToString(aliceEncKp.publicKey()));
        regBody.put("enc_key_id", B64URL.encodeToString(aliceEncKeyId));
        regBody.put("auth_public_key", B64URL.encodeToString(aliceAuthKp.publicKey()));
        regBody.put("auth_key_id", B64URL.encodeToString(aliceAuthKeyId));
        regBody.put("wrapped_enc_private_key_blob", B64URL.encodeToString(new byte[48]));
        regBody.put("wrapped_auth_private_key_blob", B64URL.encodeToString(new byte[48]));
        regBody.put("kdf_salt", B64URL.encodeToString(new byte[16]));
        regBody.put("kdf_params", kdfParams);
        regBody.put("client_password_score", 3);

        HttpClient http = HttpClient.newHttpClient();
        HttpResponse<String> regResp = http.send(
                HttpRequest.newBuilder()
                        .uri(URI.create("http://localhost:" + serverPort + "/v1/verifiers"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(regBody)))
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(regResp.statusCode()).isEqualTo(201);
        verifierId = UUID.fromString(JSON.readTree(regResp.body()).get("verifier_id").asText());
    }

    @AfterEach
    void stopMockIntermediate() {
        mockIntermediate.stop(0);
    }

    @Test
    void shareCreatesEntryAndPrintsUuid() throws Exception {
        tokenHandler = exchange -> {
            try {
                String jwt = mintJwt(installUuid, installKp.publicKey(), intKp.privateKey());
                String responseBody = "{\"bearer\":\"" + jwt + "\"}";
                byte[] body = responseBody.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
                exchange.getResponseBody().close();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };

        ShareCommand cmd = shareCommand();

        PrintStream original = System.out;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        System.setOut(new PrintStream(baos));
        int exitCode;
        try {
            exitCode = cmd.call();
        } finally {
            System.setOut(original);
        }

        assertThat(exitCode).isEqualTo(0);
        String printedId = baos.toString().trim();
        assertThat(printedId)
                .matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

        // Verify the entry row was created with the correct issuer_id
        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM entries WHERE issuer_id = ?::uuid AND entry_id = ?::uuid",
                Integer.class, installUuid.toString(), printedId);
        assertThat(count).isEqualTo(1);
    }

    @Test
    void tokenMint403ExitsNonZeroAndNoEntryCreated() throws Exception {
        tokenHandler = exchange -> {
            byte[] body = "{\"error\":\"attestation_failed\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(403, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        };

        ShareCommand cmd = shareCommand();
        int exitCode = cmd.call();

        assertThat(exitCode).isNotEqualTo(0);
        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM entries WHERE issuer_id = ?::uuid",
                Integer.class, installUuid.toString());
        assertThat(count).isEqualTo(0);
    }

    // --- helpers ---

    private ShareCommand shareCommand() {
        ShareCommand cmd = new ShareCommand();
        cmd.serverUrl = "http://localhost:" + serverPort;
        cmd.intermediateUrl = "http://localhost:" + mockIntermediatePort;
        cmd.stateDir = stateDir.toFile();
        cmd.passphrase = "testpass".toCharArray();
        cmd.verifierHandle = verifierHandle;
        cmd.plaintext = "hello from test";
        cmd.description = "test entry";
        return cmd;
    }

    private static String mintJwt(UUID installUuid, byte[] installPubKey,
                                   byte[] intPrivKey) throws Exception {
        long nowSec = System.currentTimeMillis() / 1000;

        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "EdDSA");
        header.put("typ", "JWT");

        String xB64 = B64URL.encodeToString(installPubKey);
        String jwkJson = "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" + xB64 + "\"}";
        String jkt = B64URL.encodeToString(Sha256.hash(jwkJson.getBytes(StandardCharsets.UTF_8)));

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", "urn:datawallet:issuer:" + installUuid);
        payload.put("aud", "urn:datawallet:server");
        payload.put("exp", nowSec + 120);
        payload.put("iat", nowSec);
        payload.put("cnf", Map.of("jkt", jkt));

        String headerB64 = B64URL.encodeToString(JSON.writeValueAsBytes(header));
        String payloadB64 = B64URL.encodeToString(JSON.writeValueAsBytes(payload));
        byte[] sigInput = (headerB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);
        byte[] sig = Ed25519.signDetached(intPrivKey, sigInput);
        return headerB64 + "." + payloadB64 + "." + B64URL.encodeToString(sig);
    }

    private static byte[] uuidToBytes(UUID uuid) {
        ByteBuffer buf = ByteBuffer.allocate(16);
        buf.putLong(uuid.getMostSignificantBits());
        buf.putLong(uuid.getLeastSignificantBits());
        return buf.array();
    }
}
