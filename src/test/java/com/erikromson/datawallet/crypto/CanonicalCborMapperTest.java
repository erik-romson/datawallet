package com.erikromson.datawallet.crypto;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;

class CanonicalCborMapperTest {

    private static Path fixturesDir;
    private final CanonicalCborMapper mapper = new CanonicalCborMapper();

    @BeforeAll
    static void resolveFixtures() {
        fixturesDir = resolveFixturesDir();
    }

    @ParameterizedTest
    @CsvSource({
            "envelopes/basic-1-recipient.cbor",
            "envelopes/three-recipients.cbor",
            "envelopes/allow-list-update-v2.cbor",
            "envelopes/unicode-description.cbor"
    })
    void reencodeEnvelopeFixtureIsIdentical(String relativePath) throws IOException {
        byte[] original = Files.readAllBytes(fixturesDir.resolve(relativePath));
        byte[] reencoded = mapper.reencode(original);
        assertThat(reencoded).isEqualTo(original);
    }

    @Test
    void nonCanonicalCborIsRejectedByReencode() throws IOException {
        byte[] nonCanonical = Files.readAllBytes(
                fixturesDir.resolve("envelopes/invalid/non-canonical-cbor.cbor"));
        assertThatThrownBy(() -> mapper.reencode(nonCanonical))
                .isInstanceOf(CanonicalCborException.class);
    }

    @Test
    void nonCanonicalCborIsRejectedByReadValue() throws IOException {
        byte[] nonCanonical = Files.readAllBytes(
                fixturesDir.resolve("envelopes/invalid/non-canonical-cbor.cbor"));
        assertThatThrownBy(() -> mapper.readValue(nonCanonical, Map.class))
                .isInstanceOf(CanonicalCborException.class);
    }

    @Test
    void handCraftedIndefiniteLengthArrayIsRejected() {
        // Indefinite-length array [1, 1]: 0x9f 0x01 0x01 0xff
        byte[] indefiniteArray = new byte[]{(byte) 0x9F, 0x01, 0x01, (byte) 0xFF};
        assertThatThrownBy(() -> mapper.reencode(indefiniteArray))
                .isInstanceOf(CanonicalCborException.class);
    }

    @Test
    void handCraftedNonShortestIntegerIsRejected() {
        // Value 1 encoded as 2-byte form (0x18 0x01) instead of shortest (0x01)
        // Wrap in a definite-length array: 0x81 0x18 0x01
        byte[] nonShortest = new byte[]{(byte) 0x81, 0x18, 0x01};
        assertThatThrownBy(() -> mapper.reencode(nonShortest))
                .isInstanceOf(CanonicalCborException.class);
    }

    @ParameterizedTest
    @CsvSource({
            "envelopes/basic-1-recipient.cbor,    envelopes/basic-1-recipient.signed",
            "envelopes/three-recipients.cbor,      envelopes/three-recipients.signed",
            "envelopes/allow-list-update-v2.cbor,  envelopes/allow-list-update-v2.signed",
            "envelopes/unicode-description.cbor,   envelopes/unicode-description.signed"
    })
    @SuppressWarnings("unchecked")
    void parseRemoveSignatureAndWriteMatchesSignedFixture(String cborPath, String signedPath) throws IOException {
        byte[] cborBytes = Files.readAllBytes(fixturesDir.resolve(cborPath.strip()));
        byte[] expectedSigned = Files.readAllBytes(fixturesDir.resolve(signedPath.strip()));

        Map<String, Object> envelope = mapper.readValue(cborBytes, Map.class);
        assertThat(envelope).containsKey("signature");

        LinkedHashMap<String, Object> withoutSignature = new LinkedHashMap<>(envelope);
        withoutSignature.remove("signature");

        byte[] reencoded = mapper.writeBytes(withoutSignature);
        assertThat(reencoded).isEqualTo(expectedSigned);
    }

    @ParameterizedTest
    @CsvSource({
            "0,         1",
            "23,        1",
            "24,        2",
            "255,       2",
            "256,       3",
            "65535,     3",
            "65536,     5",
            "4294967295, 5",
            "4294967296, 9"
    })
    void integerShortestFormEncoding(long value, int expectedIntBytes) {
        byte[] encoded = mapper.writeBytes(List.of(value));
        // encoded = array header (1 byte for single-element array: 0x81) + integer bytes
        int actualIntBytes = encoded.length - 1;
        assertThat(actualIntBytes)
                .as("CBOR integer byte length for value %d", value)
                .isEqualTo(expectedIntBytes);
    }

    @Test
    void keyOrderingFollowsCborCanonicalByteEncoding() {
        // "z" (1 char) must sort before "aa" (2 chars) in canonical CBOR
        // because CBOR encoding of "z" (0x61 0x7A) < "aa" (0x62 0x61 0x61)
        Map<String, Object> unordered = new LinkedHashMap<>();
        unordered.put("aa", 2);
        unordered.put("z", 1);

        byte[] encoded = mapper.writeBytes(unordered);
        // Re-read to verify order
        @SuppressWarnings("unchecked")
        Map<String, Object> decoded = mapper.readValue(encoded, Map.class);
        List<String> keys = List.copyOf(decoded.keySet());
        assertThat(keys).containsExactly("z", "aa");
    }

    @Test
    void writeAndReadRoundTrip() {
        Map<String, Object> original = new LinkedHashMap<>();
        original.put("version", 1);
        original.put("data", new byte[]{0x01, 0x02, 0x03});
        original.put("label", "test");

        byte[] encoded = mapper.writeBytes(original);
        @SuppressWarnings("unchecked")
        Map<String, Object> decoded = mapper.readValue(encoded, Map.class);

        assertThat(decoded.get("version")).isEqualTo(1);
        assertThat((byte[]) decoded.get("data")).isEqualTo(new byte[]{0x01, 0x02, 0x03});
        assertThat(decoded.get("label")).isEqualTo("test");
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
