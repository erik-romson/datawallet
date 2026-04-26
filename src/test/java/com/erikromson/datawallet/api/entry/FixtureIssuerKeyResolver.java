package com.erikromson.datawallet.api.entry;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.erikromson.datawallet.crypto.Ed25519;
import com.erikromson.datawallet.envelope.DirectoryKeyView;
import com.erikromson.datawallet.envelope.IssuerKeyResolver;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;

/**
 * IT-profile IssuerKeyResolver that uses spec fixture data to resolve the Acme signing key
 * without requiring directory records in the DB.
 */
@TestConfiguration
@Profile("it")
public class FixtureIssuerKeyResolver {

    @Bean
    @Primary
    public IssuerKeyResolver fixtureIssuerKeyResolver() throws IOException {
        Path fixturesDir = resolveFixturesDir();
        ObjectMapper json = new ObjectMapper();
        HexFormat hex = HexFormat.of();

        JsonNode keypairsInput = json.readTree(fixturesDir.resolve("inputs/keypairs.json").toFile());
        JsonNode directoryMeta = json.readTree(fixturesDir.resolve("directory/directory_meta.json").toFile());

        byte[] acmeSeed = hex.parseHex(keypairsInput.get("acme_sign").get("seed_hex").asText());
        Ed25519.KeyPair acmeKp = Ed25519.seedKeypair(acmeSeed);

        byte[] acmeKeyId = hex.parseHex(directoryMeta.get("key_ids").get("acme_sign").asText());
        UUID issuerId = bytesToUuid(hex.parseHex(directoryMeta.get("issuer_id_hex").asText()));
        long validFrom = directoryMeta.get("acme_signing_key_valid_from").asLong();
        long validUntil = directoryMeta.get("acme_signing_key_valid_until").asLong();

        return (id, keyId, atMs) -> {
            if (id.equals(issuerId) && Arrays.equals(keyId, acmeKeyId)) {
                return Optional.of(new DirectoryKeyView(
                        issuerId, acmeKeyId, acmeKp.publicKey(), "active", validFrom, validUntil
                ));
            }
            return Optional.empty();
        };
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

    private static UUID bytesToUuid(byte[] bytes) {
        ByteBuffer buf = ByteBuffer.wrap(bytes);
        return new UUID(buf.getLong(), buf.getLong());
    }
}
