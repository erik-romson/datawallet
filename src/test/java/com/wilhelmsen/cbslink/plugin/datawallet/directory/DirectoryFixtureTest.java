package com.wilhelmsen.cbslink.plugin.datawallet.directory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.Ed25519;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;

class DirectoryFixtureTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();
    private static Path fixturesDir;
    private static PinnedRoot pinnedRoot;
    private static JsonNode keypairsExpected;
    private static JsonNode directoryMeta;
    private static JsonNode timestamps;

    @BeforeAll
    static void loadFixtures() throws IOException {
        fixturesDir = resolveFixturesDir();
        DirectoryRecordCodec codec = new DirectoryRecordCodec();
        byte[] pinnedRootBytes = Files.readAllBytes(fixturesDir.resolve("directory/pinned-root.cbor"));
        pinnedRoot = codec.decodePinnedRoot(pinnedRootBytes);
        keypairsExpected = JSON.readTree(fixturesDir.resolve("inputs/keypairs.expected.json").toFile());
        directoryMeta = JSON.readTree(fixturesDir.resolve("directory/directory_meta.json").toFile());
        timestamps = JSON.readTree(fixturesDir.resolve("inputs/timestamps.json").toFile());
    }

    private static DirectoryRecordVerifier verifierAtTime(long timeMs) {
        Clock fixedClock = Clock.fixed(Instant.ofEpochMilli(timeMs), ZoneOffset.UTC);
        return new DirectoryRecordVerifier(new DirectoryRecordCodec(), fixedClock);
    }

    @Nested
    class PinnedRootParsing {

        @Test
        void pinnedRootHasExpectedStructure() {
            assertThat(pinnedRoot.version()).isEqualTo(1);
            assertThat(pinnedRoot.scheme()).isEqualTo("ed25519-quorum-v1");
            assertThat(pinnedRoot.threshold()).isEqualTo(2);
            assertThat(pinnedRoot.roots()).hasSize(3);
        }

        @Test
        void pinnedRootKeysMatchExpected() {
            List<String> expectedKeyNames = List.of("root_a", "root_b", "root_c");
            for (int i = 0; i < 3; i++) {
                PinnedRoot.RootEntry root = pinnedRoot.roots().get(i);
                String expectedPubHex = keypairsExpected.get(expectedKeyNames.get(i))
                        .get("public_key_hex").asText();
                assertThat(HEX.formatHex(root.publicKey()))
                        .as("public key for %s", expectedKeyNames.get(i))
                        .isEqualTo(expectedPubHex);

                String expectedKeyIdHex = directoryMeta.get("key_ids")
                        .get(expectedKeyNames.get(i)).asText();
                assertThat(HEX.formatHex(root.rootKeyId()))
                        .as("key_id for %s", expectedKeyNames.get(i))
                        .isEqualTo(expectedKeyIdHex);
            }
        }
    }

    @Nested
    class PositiveDirectoryRecords {

        @Test
        void verifierAliceActiveVerifies() throws IOException {
            byte[] bytes = Files.readAllBytes(fixturesDir.resolve("directory/verifier-alice-active.cbor"));
            long issuedAt = timestamps.get("t_directory_issued").asLong();
            DirectoryRecordVerifier v = verifierAtTime(issuedAt + 1000);
            DirectoryRecord record = v.verify(bytes, pinnedRoot);

            assertThat(record.version()).isEqualTo(1);
            assertThat(record.recordType()).isEqualTo("verifier");
            assertThat(record.keyUse()).isEqualTo("enc");
            assertThat(record.status()).isEqualTo("active");
            assertThat(record.rootSignatures()).hasSize(2);

            String expectedPubHex = keypairsExpected.get("alice_enc").get("public_key_hex").asText();
            assertThat(HEX.formatHex(record.publicKey())).isEqualTo(expectedPubHex);
        }

        @Test
        void verifierAliceRevokedVerifies() throws IOException {
            byte[] bytes = Files.readAllBytes(fixturesDir.resolve("directory/verifier-alice-revoked.cbor"));
            long issuedAt = timestamps.get("t_directory_issued").asLong();
            DirectoryRecordVerifier v = verifierAtTime(issuedAt + 1000);
            DirectoryRecord record = v.verify(bytes, pinnedRoot);

            assertThat(record.status()).isEqualTo("revoked");
            assertThat(record.rootSignatures()).hasSize(2);
        }

        @Test
        void issuerAcmeActiveVerifies() throws IOException {
            byte[] bytes = Files.readAllBytes(fixturesDir.resolve("directory/issuer-acme-active.cbor"));
            long issuedAt = timestamps.get("t_directory_issued").asLong();
            DirectoryRecordVerifier v = verifierAtTime(issuedAt + 1000);
            DirectoryRecord record = v.verify(bytes, pinnedRoot);

            assertThat(record.recordType()).isEqualTo("issuer");
            assertThat(record.keyUse()).isEqualTo("sign");
            assertThat(record.status()).isEqualTo("active");

            String expectedPubHex = keypairsExpected.get("acme_sign").get("public_key_hex").asText();
            assertThat(HEX.formatHex(record.publicKey())).isEqualTo(expectedPubHex);
        }

        @Test
        void allPositiveFixturesProduceCorrectSignedBytes() throws IOException {
            DirectoryRecordCodec codec = new DirectoryRecordCodec();
            for (String name : List.of("verifier-alice-active", "verifier-alice-revoked", "issuer-acme-active")) {
                byte[] bytes = Files.readAllBytes(fixturesDir.resolve("directory/" + name + ".cbor"));
                DirectoryRecord record = codec.decode(bytes);
                byte[] signedBytesFromRecord = codec.signedBytesOf(record);
                byte[] signedBytesFromBytes = codec.signedBytesOf(bytes);
                assertThat(signedBytesFromRecord)
                        .as("signedBytesOf consistency for %s", name)
                        .isEqualTo(signedBytesFromBytes);
            }
        }
    }

    @Nested
    class NegativeDirectoryRecords {

        @Test
        void oneOfTwoSigsFailsQuorumBelowThreshold() throws IOException {
            byte[] bytes = Files.readAllBytes(
                    fixturesDir.resolve("directory/invalid/one-of-two-sigs.cbor"));
            long issuedAt = timestamps.get("t_directory_issued").asLong();
            DirectoryRecordVerifier v = verifierAtTime(issuedAt + 1000);
            assertThatThrownBy(() -> v.verify(bytes, pinnedRoot))
                    .isInstanceOf(DirectoryRejection.QuorumBelowThreshold.class);
        }

        @Test
        void tamperedPublicKeyFailsSignatureInvalid() throws IOException {
            byte[] bytes = Files.readAllBytes(
                    fixturesDir.resolve("directory/invalid/tampered-public-key.cbor"));
            long issuedAt = timestamps.get("t_directory_issued").asLong();
            DirectoryRecordVerifier v = verifierAtTime(issuedAt + 1000);
            assertThatThrownBy(() -> v.verify(bytes, pinnedRoot))
                    .isInstanceOf(DirectoryRejection.SignatureInvalid.class);
        }

        @Test
        void expiredRecordFailsFreshnessCheck() throws IOException {
            byte[] bytes = Files.readAllBytes(
                    fixturesDir.resolve("directory/verifier-alice-active.cbor"));
            long issuedAt = timestamps.get("t_directory_issued").asLong();
            long eightDaysLater = issuedAt + (8L * 24 * 60 * 60 * 1000);
            DirectoryRecordVerifier v = verifierAtTime(eightDaysLater);
            assertThatThrownBy(() -> v.verify(bytes, pinnedRoot))
                    .isInstanceOf(DirectoryRejection.FreshnessExpired.class);
        }
    }

    @Nested
    class RoundTrip {

        @Test
        void encodeDecodePreservesRecord() throws IOException {
            DirectoryRecordCodec codec = new DirectoryRecordCodec();
            byte[] original = Files.readAllBytes(fixturesDir.resolve("directory/issuer-acme-active.cbor"));
            DirectoryRecord record = codec.decode(original);
            byte[] reEncoded = codec.encode(record);
            assertThat(reEncoded).isEqualTo(original);
        }
    }

    @Nested
    class RootQuorumVerification {

        @Test
        void duplicateSignaturesFromSameKeyCountOnce() throws IOException {
            DirectoryRecordCodec codec = new DirectoryRecordCodec();
            byte[] bytes = Files.readAllBytes(fixturesDir.resolve("directory/verifier-alice-active.cbor"));
            DirectoryRecord record = codec.decode(bytes);
            byte[] signedBytes = codec.signedBytesOf(bytes);

            RootSignature firstSig = record.rootSignatures().getFirst();
            List<RootSignature> duplicatedSigs = List.of(firstSig, firstSig);

            assertThatThrownBy(() -> RootQuorum.verify(signedBytes, duplicatedSigs, record.issuedAt(), pinnedRoot))
                    .isInstanceOf(DirectoryRejection.QuorumBelowThreshold.class);
        }

        @Test
        void validQuorumWithTwoDistinctKeys() throws IOException {
            DirectoryRecordCodec codec = new DirectoryRecordCodec();
            byte[] bytes = Files.readAllBytes(fixturesDir.resolve("directory/verifier-alice-active.cbor"));
            DirectoryRecord record = codec.decode(bytes);
            byte[] signedBytes = codec.signedBytesOf(bytes);

            RootQuorum.verify(signedBytes, record.rootSignatures(), record.issuedAt(), pinnedRoot);
        }
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
