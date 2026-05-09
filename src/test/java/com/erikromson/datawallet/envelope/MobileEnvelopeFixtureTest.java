package com.erikromson.datawallet.envelope;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.erikromson.datawallet.crypto.CanonicalCborMapper;
import com.erikromson.datawallet.crypto.Ed25519;
import com.erikromson.datawallet.crypto.SecretBox;
import com.erikromson.datawallet.crypto.Sha256;
import com.erikromson.datawallet.crypto.X25519;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

class MobileEnvelopeFixtureTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();
    private static Path fixturesDir;

    private static JsonNode keypairsInput;
    private static JsonNode plaintexts;
    private static JsonNode timestamps;
    private static JsonNode mobileMeta;
    private static JsonNode directoryMeta;

    @BeforeAll
    static void loadFixtures() throws IOException {
        fixturesDir = resolveFixturesDir();
        keypairsInput = JSON.readTree(fixturesDir.resolve("inputs/keypairs.json").toFile());
        plaintexts = JSON.readTree(fixturesDir.resolve("inputs/plaintexts.json").toFile());
        timestamps = JSON.readTree(fixturesDir.resolve("inputs/timestamps.json").toFile());
        mobileMeta = JSON.readTree(fixturesDir.resolve("envelopes/mobile-built/mobile_meta.json").toFile());
        directoryMeta = JSON.readTree(fixturesDir.resolve("directory/directory_meta.json").toFile());
    }

    private static Ed25519.KeyPair mobileSignKeyPair() {
        byte[] seed = HEX.parseHex(keypairsInput.get("mobile_install_sign").get("seed_hex").asText());
        return Ed25519.seedKeypair(seed);
    }

    private static IssuerKeyResolver mobileKeyResolver() {
        Ed25519.KeyPair mobile = mobileSignKeyPair();
        byte[] mobileKeyId = HEX.parseHex(directoryMeta.get("key_ids").get("mobile_install_sign").asText());
        String issuerIdHex = mobileMeta.get("single-recipient").get("issuer_id_hex").asText();
        UUID issuerId = bytesToUuid(HEX.parseHex(issuerIdHex));
        long validFrom = directoryMeta.get("acme_signing_key_valid_from").asLong();
        long validUntil = directoryMeta.get("acme_signing_key_valid_until").asLong();

        return (id, keyId, atMs) -> {
            if (id.equals(issuerId) && Arrays.equals(keyId, mobileKeyId)) {
                return Optional.of(new DirectoryKeyView(
                        issuerId, mobileKeyId, mobile.publicKey(), "active", validFrom, validUntil
                ));
            }
            return Optional.empty();
        };
    }

    @Test
    void mobileBuiltEnvelopeParsesAndVerifies() throws IOException {
        byte[] bytes = Files.readAllBytes(
                fixturesDir.resolve("envelopes/mobile-built/single-recipient.cbor"));
        EnvelopeCodec codec = new EnvelopeCodec();
        EnvelopeVerifier verifier = new EnvelopeVerifier(codec, mobileKeyResolver());
        SharedEnvelope env = verifier.verify(bytes);

        assertThat(env.version()).isEqualTo(1);
        assertThat(env.issuerLabel()).isEqualTo("Mobile Install");
        assertThat(env.description()).isEqualTo("Mobile-issued credential");
        assertThat(env.recipientWrappings()).hasSize(1);
    }

    @Test
    void signedBytesMatchFixture() throws IOException {
        EnvelopeCodec codec = new EnvelopeCodec();
        byte[] envelopeBytes = Files.readAllBytes(
                fixturesDir.resolve("envelopes/mobile-built/single-recipient.cbor"));
        byte[] expectedSigned = Files.readAllBytes(
                fixturesDir.resolve("envelopes/mobile-built/single-recipient.signed"));
        SharedEnvelope env = codec.decode(envelopeBytes);
        byte[] signedBytes = codec.signedBytesOf(env.withSignature(null));
        assertThat(signedBytes).isEqualTo(expectedSigned);
    }

    @Test
    void signatureVerifiesUnderMobileInstallSignKey() throws IOException {
        EnvelopeCodec codec = new EnvelopeCodec();
        Ed25519.KeyPair mobile = mobileSignKeyPair();

        byte[] envelopeBytes = Files.readAllBytes(
                fixturesDir.resolve("envelopes/mobile-built/single-recipient.cbor"));
        SharedEnvelope env = codec.decode(envelopeBytes);
        byte[] signedBytes = codec.signedBytesOf(env.withSignature(null));
        boolean valid = Ed25519.verifyDetached(mobile.publicKey(), signedBytes, env.signature());
        assertThat(valid).isTrue();
    }

    @Test
    void buildFromInputsMatchesFixture() throws IOException {
        JsonNode meta = mobileMeta.get("single-recipient");
        byte[] dataKey = HEX.parseHex(meta.get("data_key_hex").asText());
        byte[] ctNonce = HEX.parseHex(meta.get("ciphertext_nonce_hex").asText());
        String plaintext = plaintexts.get(meta.get("plaintext_key").asText()).asText();

        byte[] ciphertext = SecretBox.seal(
                plaintext.getBytes(StandardCharsets.UTF_8), ctNonce, dataKey);
        byte[] ciphertextHash = Sha256.hash(ciphertext);

        UUID issuerId = bytesToUuid(HEX.parseHex(meta.get("issuer_id_hex").asText()));
        UUID entryId = readEntryId("entry_mobile");
        byte[] mobileKeyId = HEX.parseHex(directoryMeta.get("key_ids").get("mobile_install_sign").asText());

        UUID aliceVerifierId = bytesToUuid(
                HEX.parseHex(directoryMeta.get("verifier_ids").get("alice").asText()));
        byte[] aliceKeyId = HEX.parseHex(directoryMeta.get("key_ids").get("alice_enc").asText());

        CanonicalCborMapper cborMapper = new CanonicalCborMapper();
        byte[] existingEnvelope = Files.readAllBytes(
                fixturesDir.resolve("envelopes/mobile-built/single-recipient.cbor"));
        @SuppressWarnings("unchecked")
        Map<String, Object> existingMap = cborMapper.readValue(existingEnvelope, Map.class);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> existingWrappings =
                (List<Map<String, Object>>) existingMap.get("recipient_wrappings");
        byte[] wrappedDataKey = (byte[]) existingWrappings.getFirst().get("wrapped_data_key");

        SharedEnvelope unsigned = new SharedEnvelope(
                1, entryId, issuerId, "Mobile Install", mobileKeyId,
                timestamps.get("t_envelope_v2").asLong(),
                "Mobile-issued credential", "xsalsa20poly1305",
                ctNonce, ciphertext, ciphertextHash,
                List.of(new RecipientWrapping(aliceVerifierId, aliceKeyId, wrappedDataKey)),
                null
        );

        EnvelopeCodec codec = new EnvelopeCodec();
        EnvelopeSigner signer = new EnvelopeSigner(codec);
        Ed25519.KeyPair mobile = mobileSignKeyPair();
        byte[] finalBytes = signer.sign(unsigned, mobile.privateKey());

        assertThat(finalBytes).isEqualTo(existingEnvelope);
    }

    @Test
    void decryptMobileEnvelopeEndToEnd() throws IOException {
        EnvelopeCodec codec = new EnvelopeCodec();
        EnvelopeVerifier verifier = new EnvelopeVerifier(codec, mobileKeyResolver());

        byte[] envelopeBytes = Files.readAllBytes(
                fixturesDir.resolve("envelopes/mobile-built/single-recipient.cbor"));
        SharedEnvelope env = verifier.verify(envelopeBytes);

        byte[] aliceSeed = HEX.parseHex(keypairsInput.get("alice_enc").get("seed_hex").asText());
        X25519.KeyPair aliceKp = X25519.seedKeypair(aliceSeed);

        byte[] wrappedDataKey = env.recipientWrappings().getFirst().wrappedDataKey();
        byte[] dataKey = com.erikromson.datawallet.crypto.SealedBox.open(
                wrappedDataKey, aliceKp.publicKey(), aliceKp.secretKey());

        byte[] decrypted = SecretBox.open(env.ciphertext(), env.ciphertextNonce(), dataKey);
        String text = new String(decrypted, StandardCharsets.UTF_8);

        JsonNode verifiedMeta = JSON.readTree(
                fixturesDir.resolve("envelopes/server-side-verified/single-recipient.json").toFile());
        String expected = verifiedMeta.get("single-recipient").get("expected_plaintext").asText();
        assertThat(text).isEqualTo(expected);
    }

    @Test
    void v1EnvelopesUnchangedByCodecAdditions() throws IOException {
        EnvelopeCodec codec = new EnvelopeCodec();
        for (String name : List.of("basic-1-recipient", "three-recipients",
                "allow-list-update-v2", "unicode-description")) {
            byte[] bytes = Files.readAllBytes(
                    fixturesDir.resolve("envelopes/" + name + ".cbor"));
            SharedEnvelope env = codec.decode(bytes);
            byte[] reencoded = codec.encode(env);
            assertThat(reencoded).as("round-trip for %s", name).isEqualTo(bytes);
        }
    }

    private static UUID readEntryId(String uuidName) throws IOException {
        List<JsonNode> uuids = JSON.readValue(
                fixturesDir.resolve("inputs/uuids.expected.json").toFile(),
                new TypeReference<>() {}
        );
        for (JsonNode row : uuids) {
            if (uuidName.equals(row.get("name").asText())) {
                return bytesToUuid(HEX.parseHex(row.get("expected_hex").asText()));
            }
        }
        return fail("UUID not found: " + uuidName);
    }

    private static UUID bytesToUuid(byte[] bytes) {
        ByteBuffer buf = ByteBuffer.wrap(bytes);
        return new UUID(buf.getLong(), buf.getLong());
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
