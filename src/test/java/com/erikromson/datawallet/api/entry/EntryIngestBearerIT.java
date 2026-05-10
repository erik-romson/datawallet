package com.erikromson.datawallet.api.entry;

import com.erikromson.datawallet.crypto.Ed25519;
import com.erikromson.datawallet.crypto.Sha256;
import com.erikromson.datawallet.directory.DirectoryRecord;
import com.erikromson.datawallet.directory.DirectoryRecordCodec;
import com.erikromson.datawallet.directory.RootSignature;
import com.erikromson.datawallet.domain.DirectoryRecordEntity;
import com.erikromson.datawallet.domain.DirectoryRecordRepository;
import com.erikromson.datawallet.persistence.PostgresTestcontainer;
import com.erikromson.datawallet.security.BearerIssuerPrincipalResolver;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "datawallet.security.issuer-mtls=false",
        "datawallet.security.issuer-bearer.enabled=true",
        "datawallet.security.issuer-bearer.audience=urn:datawallet:server"
})
@AutoConfigureMockMvc
@ActiveProfiles({"test", "it"})
@Import({PostgresTestcontainer.class, FixtureIssuerKeyResolver.class})
class EntryIngestBearerIT {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();

    @Autowired private MockMvc mvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private DirectoryRecordRepository directoryRecordRepository;
    @Autowired private JdbcTemplate jdbcTemplate;

    private byte[] intermediatePrivateKey;
    private UUID installUuid;
    private String installJkt;

    private static final String ACME_ISSUER_UUID = toUuidString("01941f297c0070509050505050505050");
    private static final String BASIC_ENTRY_ID = toUuidString("0194244fd80072428242424242424242");

    @BeforeEach
    void seedIntermediateAndInstallRecords() {
        // Clean up any prior test entries and rate-limit state that other tests may have consumed.
        jdbcTemplate.update("DELETE FROM entry_recipients WHERE entry_id = ?::uuid", BASIC_ENTRY_ID);
        jdbcTemplate.update("DELETE FROM entries WHERE entry_id = ?::uuid", BASIC_ENTRY_ID);
        jdbcTemplate.update("DELETE FROM rate_limits");

        // Clean up prior test directory records (keeping fixture ones)
        jdbcTemplate.update("DELETE FROM directory_records WHERE record_type = 'intermediate'");

        installUuid = UUID.fromString(ACME_ISSUER_UUID);

        // Generate intermediate keypair
        byte[] intSeed = new byte[32];
        for (int i = 0; i < 32; i++) intSeed[i] = (byte) (i + 1);
        Ed25519.KeyPair intKp = Ed25519.seedKeypair(intSeed);
        intermediatePrivateKey = intKp.privateKey();

        // Load the install's public key from the fixtures
        Path fixturesDir = resolveFixturesDir();
        try {
            JsonNode keypairsInput = JSON.readTree(fixturesDir.resolve("inputs/keypairs.json").toFile());
            JsonNode directoryMeta = JSON.readTree(fixturesDir.resolve("directory/directory_meta.json").toFile());

            byte[] acmeSeed = HEX.parseHex(keypairsInput.get("acme_sign").get("seed_hex").asText());
            Ed25519.KeyPair acmeKp = Ed25519.seedKeypair(acmeSeed);
            installJkt = BearerIssuerPrincipalResolver.computeJwkThumbprint(acmeKp.publicKey());

            // Seed an intermediate directory record with the test intermediate key
            DirectoryRecordCodec codec = new DirectoryRecordCodec();
            long nowMs = System.currentTimeMillis();
            byte[] intKeyId = new byte[16];
            for (int i = 0; i < 16; i++) intKeyId[i] = (byte) 0xAA;

            DirectoryRecord intRecord = new DirectoryRecord(
                    1, "intermediate", new byte[16], intKeyId,
                    intKp.publicKey(), "sign", "active",
                    nowMs - 86400_000, nowMs + 86400_000, nowMs - 86400_000,
                    List.of(new RootSignature(new byte[16], new byte[64])),
                    null, null
            );
            byte[] intRecordBytes = codec.encode(intRecord);

            directoryRecordRepository.save(new DirectoryRecordEntity(
                    "intermediate", UUID.randomUUID(), intKeyId,
                    "active", Instant.ofEpochMilli(nowMs - 86400_000),
                    Instant.ofEpochMilli(nowMs + 86400_000),
                    Instant.ofEpochMilli(nowMs - 86400_000),
                    new byte[16], null, intRecordBytes
            ));

            // Ensure an install (issuer) directory record exists for the Acme issuer
            byte[] acmeKeyId = HEX.parseHex(directoryMeta.get("key_ids").get("acme_sign").asText());
            long validFrom = directoryMeta.get("acme_signing_key_valid_from").asLong();
            long validUntil = directoryMeta.get("acme_signing_key_valid_until").asLong();

            // The issuer record already exists from the fixture resolver, but we need it
            // in the DB for the bearer resolver's cnf.jkt validation
            var existingRecords = directoryRecordRepository.findActiveBySubjectId(installUuid);
            if (existingRecords.isEmpty()) {
                DirectoryRecord issuerRecord = new DirectoryRecord(
                        1, "issuer", uuidToBytes(installUuid), acmeKeyId,
                        acmeKp.publicKey(), "sign", "active",
                        validFrom, validUntil, validFrom,
                        Collections.emptyList(), intKeyId, new byte[64]
                );
                byte[] issuerRecordBytes = codec.encode(issuerRecord);

                directoryRecordRepository.save(new DirectoryRecordEntity(
                        "issuer", installUuid, acmeKeyId,
                        "active", Instant.ofEpochMilli(validFrom),
                        Instant.ofEpochMilli(validUntil),
                        Instant.ofEpochMilli(validFrom),
                        null, intKeyId, issuerRecordBytes
                ));
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to seed test records", e);
        }
    }

    @Test
    void acceptsValidBearerAndEnvelope() throws Exception {
        byte[] cborBytes = Files.readAllBytes(
                resolveFixturesDir().resolve("envelopes/basic-1-recipient.cbor"));

        String jwt = mintBearer(installUuid, installJkt);

        MvcResult result = mvc.perform(post("/v1/entries")
                        .header("Authorization", "Bearer " + jwt)
                        .contentType("application/cbor")
                        .content(cborBytes))
                .andExpect(status().isCreated())
                .andReturn();

        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertThat(body.get("entry_id").asText()).isEqualTo(BASIC_ENTRY_ID);
        assertThat(body.get("version").asInt()).isEqualTo(1);
    }

    @Test
    void mismatchedIssuerInEnvelopeRejected() throws Exception {
        byte[] cborBytes = Files.readAllBytes(
                resolveFixturesDir().resolve("envelopes/basic-1-recipient.cbor"));

        UUID wrongUuid = UUID.randomUUID();

        // We need a directory record for the wrong UUID too for the resolver to find it
        DirectoryRecordCodec codec = new DirectoryRecordCodec();
        long nowMs = System.currentTimeMillis();
        byte[] wrongKeyId = new byte[16];
        for (int i = 0; i < 16; i++) wrongKeyId[i] = (byte) 0xBB;

        byte[] wrongSeed = new byte[32];
        for (int i = 0; i < 32; i++) wrongSeed[i] = (byte) (i + 80);
        Ed25519.KeyPair wrongKp = Ed25519.seedKeypair(wrongSeed);
        String wrongJkt = BearerIssuerPrincipalResolver.computeJwkThumbprint(wrongKp.publicKey());

        byte[] intKeyId = new byte[16];
        for (int i = 0; i < 16; i++) intKeyId[i] = (byte) 0xAA;

        DirectoryRecord wrongRecord = new DirectoryRecord(
                1, "issuer", uuidToBytes(wrongUuid), wrongKeyId,
                wrongKp.publicKey(), "sign", "active",
                nowMs - 86400_000, nowMs + 86400_000, nowMs - 86400_000,
                Collections.emptyList(), intKeyId, new byte[64]
        );
        byte[] wrongRecordBytes = codec.encode(wrongRecord);

        directoryRecordRepository.save(new DirectoryRecordEntity(
                "issuer", wrongUuid, wrongKeyId,
                "active", Instant.ofEpochMilli(nowMs - 86400_000),
                Instant.ofEpochMilli(nowMs + 86400_000),
                Instant.ofEpochMilli(nowMs - 86400_000),
                null, intKeyId, wrongRecordBytes
        ));

        String jwt = mintBearer(wrongUuid, wrongJkt);

        mvc.perform(post("/v1/entries")
                        .header("Authorization", "Bearer " + jwt)
                        .contentType("application/cbor")
                        .content(cborBytes))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error.code").value("issuer_mismatch"));

        // Cleanup
        directoryRecordRepository.deleteById(
                new DirectoryRecordEntity.DirectoryRecordId("issuer", wrongUuid, wrongKeyId));
    }

    @Test
    void replayWithinExpHits409() throws Exception {
        byte[] cborBytes = Files.readAllBytes(
                resolveFixturesDir().resolve("envelopes/basic-1-recipient.cbor"));

        String jwt = mintBearer(installUuid, installJkt);

        mvc.perform(post("/v1/entries")
                        .header("Authorization", "Bearer " + jwt)
                        .contentType("application/cbor")
                        .content(cborBytes))
                .andExpect(status().isCreated());

        // Same envelope again within exp
        mvc.perform(post("/v1/entries")
                        .header("Authorization", "Bearer " + jwt)
                        .contentType("application/cbor")
                        .content(cborBytes))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error.code").value("entry_id_taken"));
    }

    @Test
    void bearerWithMismatchedJktRejected() throws Exception {
        byte[] cborBytes = Files.readAllBytes(
                resolveFixturesDir().resolve("envelopes/basic-1-recipient.cbor"));

        // Use a wrong jkt thumbprint (from a different key)
        String wrongJkt = "wrong-thumbprint-value-definitely-not-matching";
        String jwt = mintBearer(installUuid, wrongJkt);

        mvc.perform(post("/v1/entries")
                        .header("Authorization", "Bearer " + jwt)
                        .contentType("application/cbor")
                        .content(cborBytes))
                .andExpect(status().isUnauthorized());
    }

    private String mintBearer(UUID uuid, String jkt) {
        try {
            long nowSec = System.currentTimeMillis() / 1000;
            Map<String, Object> header = new LinkedHashMap<>();
            header.put("alg", "EdDSA");
            header.put("typ", "JWT");

            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("iss", "urn:datawallet:issuer:" + uuid);
            payload.put("aud", "urn:datawallet:server");
            payload.put("exp", nowSec + 120);
            payload.put("iat", nowSec);
            payload.put("cnf", Map.of("jkt", jkt));

            String headerB64 = B64URL.encodeToString(JSON.writeValueAsBytes(header));
            String payloadB64 = B64URL.encodeToString(JSON.writeValueAsBytes(payload));
            byte[] signingInput = (headerB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);
            byte[] sig = Ed25519.signDetached(intermediatePrivateKey, signingInput);
            return headerB64 + "." + payloadB64 + "." + B64URL.encodeToString(sig);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static Path resolveFixturesDir() {
        Path dir = Path.of(System.getProperty("user.dir"));
        while (dir != null) {
            Path candidate = dir.resolve("spec/fixtures");
            if (Files.isDirectory(candidate)) return candidate;
            dir = dir.getParent();
        }
        throw new IllegalStateException("spec/fixtures not found");
    }

    private static String toUuidString(String hex) {
        return hex.substring(0, 8) + "-" + hex.substring(8, 12) + "-"
                + hex.substring(12, 16) + "-" + hex.substring(16, 20) + "-"
                + hex.substring(20);
    }

    private static byte[] uuidToBytes(UUID uuid) {
        byte[] bytes = new byte[16];
        long msb = uuid.getMostSignificantBits();
        long lsb = uuid.getLeastSignificantBits();
        for (int i = 0; i < 8; i++) {
            bytes[i] = (byte) (msb >>> (56 - i * 8));
            bytes[i + 8] = (byte) (lsb >>> (56 - i * 8));
        }
        return bytes;
    }
}
