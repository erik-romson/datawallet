package com.wilhelmsen.cbslink.plugin.datawallet.api.admin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wilhelmsen.cbslink.plugin.datawallet.api.entry.FixtureIssuerKeyResolver;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.CanonicalCborMapper;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.Ed25519;
import com.wilhelmsen.cbslink.plugin.datawallet.directory.DirectoryRecordCodec;
import com.wilhelmsen.cbslink.plugin.datawallet.directory.DirectoryRecordVerifier;
import com.wilhelmsen.cbslink.plugin.datawallet.domain.DirectoryRecordEntity;
import com.wilhelmsen.cbslink.plugin.datawallet.domain.DirectoryRecordRepository;
import com.wilhelmsen.cbslink.plugin.datawallet.persistence.PostgresTestcontainer;
import com.wilhelmsen.cbslink.plugin.datawallet.security.StubAdminPrincipalResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"test", "it"})
@Import({PostgresTestcontainer.class, FixtureIssuerKeyResolver.class})
class AdminDirectoryControllerIT {

    /**
     * Fixture root keys were issued at t_directory_issued (Jan 1, 2025) and valid until Jan 1, 2026.
     * Fix the verifier clock to Jan 1, 2025 + 1 hour so the freshness check passes.
     */
    @TestConfiguration
    static class ClockOverride {
        // t_directory_issued = 1735689000000 ms → Jan 1, 2025
        private static final long FIXED_CLOCK_MS = 1735689000000L + 3_600_000L;

        @Bean
        @Primary
        public DirectoryRecordVerifier fixedClockDirectoryRecordVerifier(DirectoryRecordCodec codec) {
            Clock fixed = Clock.fixed(Instant.ofEpochMilli(FIXED_CLOCK_MS), ZoneOffset.UTC);
            return new DirectoryRecordVerifier(codec, fixed);
        }
    }

    // Use issued_at within the fixture root-key validity window
    private static final long ISSUED_AT = 1735689000000L + 1_000L;

    @Autowired private MockMvc mvc;
    @Autowired private DirectoryRecordRepository directoryRecordRepository;
    @Autowired private JdbcTemplate jdbcTemplate;

    private static final HexFormat HEX = HexFormat.of();
    private CanonicalCborMapper cbor;
    private JsonNode keypairs;
    private JsonNode directoryMeta;
    private Ed25519.KeyPair rootAKp;
    private Ed25519.KeyPair rootBKp;
    private byte[] rootAKeyId;
    private byte[] rootBKeyId;

    private static final UUID TEST_SUBJECT_ID = UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    private static final byte[] TEST_KEY_ID = HEX.parseHex("aabbccddeeff00112233445566778899");

    @BeforeEach
    void setUp() throws Exception {
        cbor = new CanonicalCborMapper();

        Path fixturesDir = resolveFixturesDir();
        ObjectMapper json = new ObjectMapper();
        keypairs = json.readTree(fixturesDir.resolve("inputs/keypairs.json").toFile());
        directoryMeta = json.readTree(fixturesDir.resolve("directory/directory_meta.json").toFile());

        rootAKp = Ed25519.seedKeypair(HEX.parseHex(keypairs.get("root_a").get("seed_hex").asText()));
        rootBKp = Ed25519.seedKeypair(HEX.parseHex(keypairs.get("root_b").get("seed_hex").asText()));
        rootAKeyId = HEX.parseHex(directoryMeta.get("key_ids").get("root_a").asText());
        rootBKeyId = HEX.parseHex(directoryMeta.get("key_ids").get("root_b").asText());

        jdbcTemplate.update("DELETE FROM directory_records WHERE subject_id = ?::uuid",
                TEST_SUBJECT_ID.toString());
    }

    @Test
    void publishFreshRecord_returns201AndPersists() throws Exception {
        byte[] recordCbor = buildSignedRecord("verifier", TEST_SUBJECT_ID, TEST_KEY_ID,
                new byte[32], "enc", "active", ISSUED_AT);

        mvc.perform(post("/v1/admin/directory")
                        .contentType("application/cbor")
                        .header(StubAdminPrincipalResolver.HEADER, StubAdminPrincipalResolver.HEADER_VALUE)
                        .content(recordCbor))
                .andExpect(status().isCreated());

        DirectoryRecordEntity.DirectoryRecordId pk =
                new DirectoryRecordEntity.DirectoryRecordId("verifier", TEST_SUBJECT_ID, TEST_KEY_ID);
        assertThat(directoryRecordRepository.findById(pk)).isPresent();
    }

    @Test
    void publishRevokedRecord_clearsPendingRevocationFlag() throws Exception {
        long olderIssuedAt = ISSUED_AT - 10_000L;
        jdbcTemplate.update("""
                INSERT INTO directory_records (record_type, subject_id, key_id, status,
                    valid_from, valid_until, issued_at, root_key_id, signed_record, pending_revocation)
                VALUES ('verifier', ?::uuid, ?, 'active', now()-interval '1 day', now()+interval '1 year',
                    to_timestamp(? / 1000.0), ?, ?, true)
                """,
                TEST_SUBJECT_ID.toString(), TEST_KEY_ID, olderIssuedAt, rootAKeyId, new byte[]{1});

        byte[] revokedCbor = buildSignedRecord("verifier", TEST_SUBJECT_ID, TEST_KEY_ID,
                new byte[32], "enc", "revoked", ISSUED_AT);

        mvc.perform(post("/v1/admin/directory")
                        .contentType("application/cbor")
                        .header(StubAdminPrincipalResolver.HEADER, StubAdminPrincipalResolver.HEADER_VALUE)
                        .content(revokedCbor))
                .andExpect(status().isCreated());

        DirectoryRecordEntity.DirectoryRecordId pk =
                new DirectoryRecordEntity.DirectoryRecordId("verifier", TEST_SUBJECT_ID, TEST_KEY_ID);
        DirectoryRecordEntity saved = directoryRecordRepository.findById(pk).orElseThrow();
        assertThat(saved.getStatus()).isEqualTo("revoked");
        assertThat(saved.isPendingRevocation()).isFalse();
    }

    @Test
    void publishStaleRecord_returns409() throws Exception {
        long fresherIssuedAt = ISSUED_AT + 60_000L;
        jdbcTemplate.update("""
                INSERT INTO directory_records (record_type, subject_id, key_id, status,
                    valid_from, valid_until, issued_at, root_key_id, signed_record, pending_revocation)
                VALUES ('verifier', ?::uuid, ?, 'active', now()-interval '1 day', now()+interval '1 year',
                    to_timestamp(? / 1000.0), ?, ?, false)
                """,
                TEST_SUBJECT_ID.toString(), TEST_KEY_ID, fresherIssuedAt, rootAKeyId, new byte[]{1});

        // Try to publish with older issued_at → stale
        byte[] staleRecord = buildSignedRecord("verifier", TEST_SUBJECT_ID, TEST_KEY_ID,
                new byte[32], "enc", "active", ISSUED_AT);

        mvc.perform(post("/v1/admin/directory")
                        .contentType("application/cbor")
                        .header(StubAdminPrincipalResolver.HEADER, StubAdminPrincipalResolver.HEADER_VALUE)
                        .content(staleRecord))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error.code").value("directory_record_stale"));
    }

    @Test
    void publishWithoutAdminPrincipal_returns401() throws Exception {
        byte[] recordCbor = buildSignedRecord("verifier", TEST_SUBJECT_ID, TEST_KEY_ID,
                new byte[32], "enc", "active", ISSUED_AT);

        mvc.perform(post("/v1/admin/directory")
                        .contentType("application/cbor")
                        .content(recordCbor))
                .andExpect(status().isUnauthorized());
    }

    private byte[] buildSignedRecord(String recordType, UUID subjectId, byte[] keyId,
                                      byte[] publicKey, String keyUse, String status, long issuedAtMs) {
        // valid_from and valid_until must contain issuedAtMs for root key check
        long validFrom = 1735600000000L;     // from fixture
        long validUntil = 1767225600000L;    // from fixture (Jan 1, 2026)

        Map<String, Object> withoutSigs = new LinkedHashMap<>();
        withoutSigs.put("version", 1);
        withoutSigs.put("record_type", recordType);
        withoutSigs.put("subject_id", uuidToBytes(subjectId));
        withoutSigs.put("key_id", keyId);
        withoutSigs.put("public_key", publicKey);
        withoutSigs.put("key_use", keyUse);
        withoutSigs.put("status", status);
        withoutSigs.put("valid_from", validFrom);
        withoutSigs.put("valid_until", validUntil);
        withoutSigs.put("issued_at", issuedAtMs);

        byte[] signedBytes = cbor.writeBytes(withoutSigs);
        byte[] sigA = Ed25519.signDetached(rootAKp.privateKey(), signedBytes);
        byte[] sigB = Ed25519.signDetached(rootBKp.privateKey(), signedBytes);

        List<Map<String, Object>> sigs = new ArrayList<>();
        Map<String, Object> sigMapA = new LinkedHashMap<>();
        sigMapA.put("root_key_id", rootAKeyId);
        sigMapA.put("signature", sigA);
        sigs.add(sigMapA);
        Map<String, Object> sigMapB = new LinkedHashMap<>();
        sigMapB.put("root_key_id", rootBKeyId);
        sigMapB.put("signature", sigB);
        sigs.add(sigMapB);

        withoutSigs.put("root_signatures", sigs);
        return cbor.writeBytes(withoutSigs);
    }

    private static byte[] uuidToBytes(UUID uuid) {
        ByteBuffer buf = ByteBuffer.allocate(16);
        buf.putLong(uuid.getMostSignificantBits());
        buf.putLong(uuid.getLeastSignificantBits());
        return buf.array();
    }

    private static Path resolveFixturesDir() {
        Path dir = Paths.get(System.getProperty("user.dir"));
        for (int i = 0; i < 5; i++) {
            Path candidate = dir.resolve("spec").resolve("fixtures");
            if (Files.isDirectory(candidate) && Files.exists(candidate.resolve("manifest.json"))) {
                return candidate;
            }
            dir = dir.getParent();
            if (dir == null) break;
        }
        throw new IllegalStateException("Could not find spec/fixtures directory");
    }
}
