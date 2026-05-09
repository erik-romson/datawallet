package com.erikromson.datawallet.directory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;

class DirectoryRecordVerifierChainTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();

    private static Path fixturesDir;
    private static PinnedRoot pinnedRoot;
    private static JsonNode timestamps;
    private static JsonNode intermediateMeta;

    @BeforeAll
    static void loadFixtures() throws IOException {
        fixturesDir = resolveFixturesDir();
        DirectoryRecordCodec codec = new DirectoryRecordCodec();
        byte[] pinnedRootBytes = Files.readAllBytes(fixturesDir.resolve("directory/pinned-root.cbor"));
        pinnedRoot = codec.decodePinnedRoot(pinnedRootBytes);
        timestamps = JSON.readTree(fixturesDir.resolve("inputs/timestamps.json").toFile());
        intermediateMeta = JSON.readTree(
                fixturesDir.resolve("directory/intermediate-record/intermediate_meta.json").toFile());
    }

    private static DirectoryRecordVerifier verifierAtTime(long timeMs) {
        Clock fixedClock = Clock.fixed(Instant.ofEpochMilli(timeMs), ZoneOffset.UTC);
        return new DirectoryRecordVerifier(new DirectoryRecordCodec(), fixedClock);
    }

    private static long issuedAt() {
        return timestamps.get("t_directory_issued").asLong();
    }

    /** Lookup backed by the intermediate fixture file. */
    private static DirectoryRecordVerifier.ParentLookup intermediateFileLookup() throws IOException {
        byte[] intermediateBytes = Files.readAllBytes(
                fixturesDir.resolve("directory/intermediate-record/intermediate.cbor"));
        byte[] intermediateKeyId = HEX.parseHex(
                intermediateMeta.get("intermediate_key_id_hex").asText());
        return parentKeyId -> {
            if (Arrays.equals(parentKeyId, intermediateKeyId)) return intermediateBytes;
            throw new DirectoryRejection.ParentNotFound("No fixture for parent_key_id=" + HEX.formatHex(parentKeyId));
        };
    }

    @Nested
    class V1BackwardsCompat {

        @Test
        void v1RecordDecodesAndReEncodesIdentically() throws IOException {
            DirectoryRecordCodec codec = new DirectoryRecordCodec();
            byte[] original = Files.readAllBytes(fixturesDir.resolve("directory/issuer-acme-active.cbor"));
            DirectoryRecord record = codec.decode(original);

            assertThat(record.parentKeyId()).isNull();
            assertThat(record.parentSignature()).isNull();
            assertThat(record.rootSignatures()).hasSize(2);

            byte[] reEncoded = codec.encode(record);
            assertThat(reEncoded).isEqualTo(original);
        }

        @Test
        void v1RecordVerifiesWithNewCodec() throws IOException {
            byte[] bytes = Files.readAllBytes(fixturesDir.resolve("directory/issuer-acme-active.cbor"));
            DirectoryRecordVerifier v = verifierAtTime(issuedAt() + 1000);
            DirectoryRecord record = v.verify(bytes, pinnedRoot);
            assertThat(record.recordType()).isEqualTo("issuer");
        }
    }

    @Nested
    class ValidChain {

        @Test
        void intermediateRecordVerifiesAsRootSigned() throws IOException {
            byte[] bytes = Files.readAllBytes(
                    fixturesDir.resolve("directory/intermediate-record/intermediate.cbor"));
            DirectoryRecordVerifier v = verifierAtTime(issuedAt() + 1000);
            DirectoryRecord record = v.verify(bytes, pinnedRoot);

            assertThat(record.recordType()).isEqualTo("intermediate");
            assertThat(record.parentKeyId()).isNull();
            assertThat(record.rootSignatures()).hasSize(2);
        }

        @Test
        void issuerUnderIntermediateVerifiesFullChain() throws IOException {
            byte[] bytes = Files.readAllBytes(
                    fixturesDir.resolve("directory/intermediate-record/issuer-under-intermediate.cbor"));
            DirectoryRecordVerifier v = verifierAtTime(issuedAt() + 1000);
            DirectoryRecord record = v.verify(bytes, pinnedRoot, intermediateFileLookup());

            assertThat(record.recordType()).isEqualTo("issuer");
            assertThat(record.parentKeyId()).isNotNull();
            assertThat(record.parentSignature()).isNotNull();
        }

        @Test
        void issuerUnderIntermediateSignedBytesConsistent() throws IOException {
            DirectoryRecordCodec codec = new DirectoryRecordCodec();
            byte[] bytes = Files.readAllBytes(
                    fixturesDir.resolve("directory/intermediate-record/issuer-under-intermediate.cbor"));
            DirectoryRecord record = codec.decode(bytes);
            byte[] fromRecord = codec.signedBytesOf(record);
            byte[] fromBytes = codec.signedBytesOf(bytes);
            assertThat(fromRecord).isEqualTo(fromBytes);
        }
    }

    @Nested
    class ChainRejections {

        @Test
        void chainTooDeepRejected() throws IOException {
            byte[] chainTooDeepBytes = Files.readAllBytes(
                    fixturesDir.resolve("directory/intermediate-record/chain-too-deep.cbor"));
            byte[] deepIntermediateBytes = Files.readAllBytes(
                    fixturesDir.resolve("directory/intermediate-record/deep-intermediate.cbor"));
            byte[] wrongIntermediateKeyId = HEX.parseHex(
                    intermediateMeta.get("wrong_intermediate_key_id_hex").asText());

            DirectoryRecordVerifier.ParentLookup lookup = parentKeyId -> {
                if (Arrays.equals(parentKeyId, wrongIntermediateKeyId)) return deepIntermediateBytes;
                throw new DirectoryRejection.ParentNotFound("Not found");
            };

            DirectoryRecordVerifier v = verifierAtTime(issuedAt() + 1000);
            assertThatThrownBy(() -> v.verify(chainTooDeepBytes, pinnedRoot, lookup))
                    .isInstanceOf(DirectoryRejection.ChainTooDeep.class);
        }

        @Test
        void wrongParentSignatureRejected() throws IOException {
            byte[] bytes = Files.readAllBytes(
                    fixturesDir.resolve("directory/intermediate-record/wrong-parent-signature.cbor"));
            DirectoryRecordVerifier v = verifierAtTime(issuedAt() + 1000);
            assertThatThrownBy(() -> v.verify(bytes, pinnedRoot, intermediateFileLookup()))
                    .isInstanceOf(DirectoryRejection.ParentSignatureInvalid.class);
        }

        @Test
        void bothSignatureContainersRejected() throws IOException {
            byte[] bytes = Files.readAllBytes(
                    fixturesDir.resolve("directory/intermediate-record/both-signature-containers.cbor"));
            DirectoryRecordVerifier v = verifierAtTime(issuedAt() + 1000);
            assertThatThrownBy(() -> v.verify(bytes, pinnedRoot))
                    .isInstanceOf(DirectoryRejection.SignatureContainerConflict.class);
        }

        @Test
        void noSignatureContainerRejected() throws IOException {
            byte[] bytes = Files.readAllBytes(
                    fixturesDir.resolve("directory/intermediate-record/no-signature-container.cbor"));
            DirectoryRecordVerifier v = verifierAtTime(issuedAt() + 1000);
            assertThatThrownBy(() -> v.verify(bytes, pinnedRoot))
                    .isInstanceOf(DirectoryRejection.SignatureContainerMissing.class);
        }

        @Test
        void parentNotFoundRejectedForChainRecord() throws IOException {
            byte[] bytes = Files.readAllBytes(
                    fixturesDir.resolve("directory/intermediate-record/issuer-under-intermediate.cbor"));
            DirectoryRecordVerifier v = verifierAtTime(issuedAt() + 1000);
            // no-op lookup → throws ParentNotFound
            assertThatThrownBy(() -> v.verify(bytes, pinnedRoot))
                    .isInstanceOf(DirectoryRejection.ParentNotFound.class);
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
