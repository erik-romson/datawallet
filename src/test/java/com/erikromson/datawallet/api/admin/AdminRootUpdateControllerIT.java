package com.erikromson.datawallet.api.admin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.erikromson.datawallet.api.entry.FixtureIssuerKeyResolver;
import com.erikromson.datawallet.crypto.CanonicalCborMapper;
import com.erikromson.datawallet.crypto.Ed25519;
import com.erikromson.datawallet.directory.PinnedRoot;
import com.erikromson.datawallet.directory.PinnedRootHolder;
import com.erikromson.datawallet.persistence.PostgresTestcontainer;
import com.erikromson.datawallet.security.StubAdminPrincipalResolver;
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

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"test", "it"})
@Import({PostgresTestcontainer.class, FixtureIssuerKeyResolver.class, AdminRootUpdateControllerIT.PinnedRootOverride.class})
class AdminRootUpdateControllerIT {

    /**
     * The fixture pinned root has root keys valid until Jan 1, 2026 (expired).
     * Override the PinnedRootHolder with a version that has the same keys but far-future validity.
     */
    @TestConfiguration
    public static class PinnedRootOverride {

        private static final HexFormat HEX = HexFormat.of();

        @Bean
        @Primary
        public PinnedRootHolder extendedPinnedRootHolder() throws Exception {
            Path fixturesDir = resolveFixturesDir();
            ObjectMapper json = new ObjectMapper();
            JsonNode keypairs = json.readTree(fixturesDir.resolve("inputs/keypairs.json").toFile());
            JsonNode directoryMeta = json.readTree(fixturesDir.resolve("directory/directory_meta.json").toFile());

            long validFrom = Instant.now().minusSeconds(86400L * 365).toEpochMilli();
            long validUntil = Instant.now().plusSeconds(86400L * 365).toEpochMilli();

            List<PinnedRoot.RootEntry> roots = List.of(
                    rootEntry(keypairs, directoryMeta, "root_a", validFrom, validUntil, HEX),
                    rootEntry(keypairs, directoryMeta, "root_b", validFrom, validUntil, HEX),
                    rootEntry(keypairs, directoryMeta, "root_c", validFrom, validUntil, HEX)
            );
            PinnedRoot root = new PinnedRoot(1, "ed25519-quorum-v1", 2, roots);
            return new PinnedRootHolder(root);
        }

        private static PinnedRoot.RootEntry rootEntry(JsonNode keypairs, JsonNode directoryMeta,
                                                       String name, long validFrom, long validUntil,
                                                       HexFormat hex) throws Exception {
            byte[] seed = hex.parseHex(keypairs.get(name).get("seed_hex").asText());
            byte[] keyId = hex.parseHex(directoryMeta.get("key_ids").get(name).asText());
            Ed25519.KeyPair kp = Ed25519.seedKeypair(seed);
            return new PinnedRoot.RootEntry(keyId, kp.publicKey(), validFrom, validUntil);
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

    @Autowired private MockMvc mvc;
    @Autowired private PinnedRootHolder pinnedRootHolder;
    @Autowired private JdbcTemplate jdbcTemplate;

    private static final HexFormat HEX = HexFormat.of();
    private CanonicalCborMapper cbor;
    private Ed25519.KeyPair rootAKp;
    private Ed25519.KeyPair rootBKp;
    private Ed25519.KeyPair rootCKp;
    private byte[] rootAKeyId;
    private byte[] rootBKeyId;
    private byte[] rootCKeyId;

    @BeforeEach
    void setUp() throws Exception {
        cbor = new CanonicalCborMapper();

        Path fixturesDir = resolveFixturesDir();
        ObjectMapper json = new ObjectMapper();
        JsonNode keypairs = json.readTree(fixturesDir.resolve("inputs/keypairs.json").toFile());
        JsonNode directoryMeta = json.readTree(fixturesDir.resolve("directory/directory_meta.json").toFile());

        rootAKp = Ed25519.seedKeypair(HEX.parseHex(keypairs.get("root_a").get("seed_hex").asText()));
        rootBKp = Ed25519.seedKeypair(HEX.parseHex(keypairs.get("root_b").get("seed_hex").asText()));
        rootCKp = Ed25519.seedKeypair(HEX.parseHex(keypairs.get("root_c").get("seed_hex").asText()));
        rootAKeyId = HEX.parseHex(directoryMeta.get("key_ids").get("root_a").asText());
        rootBKeyId = HEX.parseHex(directoryMeta.get("key_ids").get("root_b").asText());
        rootCKeyId = HEX.parseHex(directoryMeta.get("key_ids").get("root_c").asText());

        jdbcTemplate.update("DELETE FROM pinned_root_history");
    }

    @Test
    void publishValidRootUpdate_returns201AndUpdatesHolder() throws Exception {
        // Build new root with threshold=3 (currently 2) — verifying the holder updates
        Map<String, Object> newPinnedRootMap = buildPinnedRootMap(3);

        byte[] rootUpdateCbor = buildRootUpdateCbor(newPinnedRootMap, rootAKp, rootBKp);

        mvc.perform(post("/v1/admin/root-update")
                        .contentType("application/cbor")
                        .header(StubAdminPrincipalResolver.HEADER, StubAdminPrincipalResolver.HEADER_VALUE)
                        .content(rootUpdateCbor))
                .andExpect(status().isCreated());

        assertThat(pinnedRootHolder.get().threshold()).isEqualTo(3);
    }

    @Test
    void publishBelowThreshold_returns422() throws Exception {
        Map<String, Object> newPinnedRootMap = buildPinnedRootMap(2);

        // Sign with only 1 root key (below threshold of 2)
        byte[] rootUpdateCbor = buildRootUpdateCbor(newPinnedRootMap, rootAKp);

        mvc.perform(post("/v1/admin/root-update")
                        .contentType("application/cbor")
                        .header(StubAdminPrincipalResolver.HEADER, StubAdminPrincipalResolver.HEADER_VALUE)
                        .content(rootUpdateCbor))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error.code").value("quorum_below_threshold"));
    }

    @Test
    void publishWithoutAdminPrincipal_returns401() throws Exception {
        Map<String, Object> newPinnedRootMap = buildPinnedRootMap(2);
        byte[] rootUpdateCbor = buildRootUpdateCbor(newPinnedRootMap, rootAKp, rootBKp);

        mvc.perform(post("/v1/admin/root-update")
                        .contentType("application/cbor")
                        .content(rootUpdateCbor))
                .andExpect(status().isUnauthorized());
    }

    private byte[] buildRootUpdateCbor(Map<String, Object> newPinnedRootMap, Ed25519.KeyPair... signers) {
        long issuedAt = Instant.now().toEpochMilli();

        Map<String, Object> unsigned = new LinkedHashMap<>();
        unsigned.put("version", 1);
        unsigned.put("old_root_key_ids", List.of(rootAKeyId, rootBKeyId, rootCKeyId));
        unsigned.put("new_pinned_root", newPinnedRootMap);
        unsigned.put("issued_at", issuedAt);

        byte[] signedBytes = cbor.writeBytes(unsigned);

        byte[][] keyIds = {rootAKeyId, rootBKeyId, rootCKeyId};
        List<Map<String, Object>> sigs = new ArrayList<>();
        for (int i = 0; i < signers.length; i++) {
            byte[] sig = Ed25519.signDetached(signers[i].privateKey(), signedBytes);
            Map<String, Object> sigMap = new LinkedHashMap<>();
            sigMap.put("root_key_id", keyIds[i]);
            sigMap.put("signature", sig);
            sigs.add(sigMap);
        }

        unsigned.put("old_root_signatures", sigs);
        return cbor.writeBytes(unsigned);
    }

    private Map<String, Object> buildPinnedRootMap(int threshold) {
        long validFrom = Instant.now().minusSeconds(86400L * 365).toEpochMilli();
        long validUntil = Instant.now().plusSeconds(86400L * 365).toEpochMilli();

        List<Map<String, Object>> roots = List.of(
                rootEntry(rootAKeyId, rootAKp.publicKey(), validFrom, validUntil),
                rootEntry(rootBKeyId, rootBKp.publicKey(), validFrom, validUntil),
                rootEntry(rootCKeyId, rootCKp.publicKey(), validFrom, validUntil)
        );

        Map<String, Object> map = new LinkedHashMap<>();
        map.put("version", 1);
        map.put("scheme", "ed25519-quorum-v1");
        map.put("threshold", threshold);
        map.put("roots", roots);
        return map;
    }

    private Map<String, Object> rootEntry(byte[] keyId, byte[] pub, long validFrom, long validUntil) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("root_key_id", keyId);
        entry.put("public_key", pub);
        entry.put("valid_from", validFrom);
        entry.put("valid_until", validUntil);
        return entry;
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
