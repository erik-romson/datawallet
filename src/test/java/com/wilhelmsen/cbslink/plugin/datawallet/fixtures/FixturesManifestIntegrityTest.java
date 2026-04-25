package com.wilhelmsen.cbslink.plugin.datawallet.fixtures;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

class FixturesManifestIntegrityTest {

    private static Path fixturesDir;
    private static JsonNode manifest;

    @BeforeAll
    static void loadManifest() throws IOException {
        fixturesDir = resolveFixturesDir();
        Path manifestPath = fixturesDir.resolve("manifest.json");
        assertThat(manifestPath).as("manifest.json must exist at %s", manifestPath).exists();
        manifest = new ObjectMapper().readTree(manifestPath.toFile());
        assertThat(manifest.has("files")).as("manifest must have 'files' array").isTrue();
    }

    @Test
    void allManifestEntriesMatchSha256() throws Exception {
        JsonNode files = manifest.get("files");
        assertThat(files.isArray()).isTrue();
        assertThat(files.size()).as("manifest must list at least one file").isGreaterThan(0);

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        HexFormat hex = HexFormat.of();

        for (JsonNode entry : files) {
            String relPath = entry.get("path").asText();
            String expectedHash = entry.get("sha256").asText();

            Path filePath = fixturesDir.resolve(relPath);
            assertThat(filePath)
                    .as("fixture file must exist: %s", relPath)
                    .exists();

            byte[] content = Files.readAllBytes(filePath);
            sha256.reset();
            String actualHash = hex.formatHex(sha256.digest(content));

            assertThat(actualHash)
                    .as("SHA-256 mismatch for %s", relPath)
                    .isEqualTo(expectedHash);
        }
    }

    @Test
    void manifestHasSpecVersion() {
        assertThat(manifest.has("spec_version")).as("manifest must have spec_version").isTrue();
        assertThat(manifest.get("spec_version").asInt()).isEqualTo(1);
    }

    @Test
    void manifestCoversMinimumFixtures() {
        JsonNode files = manifest.get("files");
        assertThat(countByCategory(files, "wrapped")).as("wrapped blobs").isGreaterThanOrEqualTo(4);
        assertThat(countByCategory(files, "envelope")).as("valid envelopes").isGreaterThanOrEqualTo(4);
        assertThat(countByCategory(files, "envelope-invalid")).as("invalid envelopes").isGreaterThanOrEqualTo(5);
        assertThat(countByCategory(files, "directory")).as("directory records").isGreaterThanOrEqualTo(4);
        assertThat(countByCategory(files, "directory-invalid")).as("invalid directory records").isGreaterThanOrEqualTo(2);
        assertThat(countByCategory(files, "auth")).as("auth vectors").isGreaterThanOrEqualTo(2);
        assertThat(countByCategory(files, "audit")).as("audit vectors").isGreaterThanOrEqualTo(2);
        assertThat(countByCategory(files, "fingerprint")).as("fingerprint vectors").isGreaterThanOrEqualTo(1);
    }

    private static long countByCategory(JsonNode files, String category) {
        long count = 0;
        for (JsonNode entry : files) {
            if (category.equals(entry.get("category").asText())) {
                count++;
            }
        }
        return count;
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
        return fail("Could not find spec/fixtures directory from " + System.getProperty("user.dir"));
    }
}
