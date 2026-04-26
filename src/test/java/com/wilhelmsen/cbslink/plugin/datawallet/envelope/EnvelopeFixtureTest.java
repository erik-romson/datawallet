package com.wilhelmsen.cbslink.plugin.datawallet.envelope;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.CanonicalCborMapper;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.Ed25519;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.SecretBox;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.Sha256;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.X25519;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;

class EnvelopeFixtureTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();
    private static Path fixturesDir;

    private static JsonNode keypairsInput;
    private static JsonNode keypairsExpected;
    private static JsonNode plaintexts;
    private static JsonNode timestamps;
    private static JsonNode envelopeMeta;
    private static JsonNode directoryMeta;

    @BeforeAll
    static void loadFixtures() throws IOException {
        fixturesDir = resolveFixturesDir();
        keypairsInput = JSON.readTree(fixturesDir.resolve("inputs/keypairs.json").toFile());
        keypairsExpected = JSON.readTree(fixturesDir.resolve("inputs/keypairs.expected.json").toFile());
        plaintexts = JSON.readTree(fixturesDir.resolve("inputs/plaintexts.json").toFile());
        timestamps = JSON.readTree(fixturesDir.resolve("inputs/timestamps.json").toFile());
        envelopeMeta = JSON.readTree(fixturesDir.resolve("envelopes/envelope_meta.json").toFile());
        directoryMeta = JSON.readTree(fixturesDir.resolve("directory/directory_meta.json").toFile());
    }

    private static Ed25519.KeyPair acmeSignKeyPair() {
        byte[] seed = HEX.parseHex(keypairsInput.get("acme_sign").get("seed_hex").asText());
        return Ed25519.seedKeypair(seed);
    }

    private static IssuerKeyResolver acmeKeyResolver() {
        Ed25519.KeyPair acme = acmeSignKeyPair();
        byte[] acmeKeyId = HEX.parseHex(directoryMeta.get("key_ids").get("acme_sign").asText());
        UUID issuerId = bytesToUuid(HEX.parseHex(directoryMeta.get("issuer_id_hex").asText()));
        long validFrom = directoryMeta.get("acme_signing_key_valid_from").asLong();
        long validUntil = directoryMeta.get("acme_signing_key_valid_until").asLong();

        return (id, keyId, atMs) -> {
            if (id.equals(issuerId) && Arrays.equals(keyId, acmeKeyId)) {
                return Optional.of(new DirectoryKeyView(
                        issuerId, acmeKeyId, acme.publicKey(), "active", validFrom, validUntil
                ));
            }
            return Optional.empty();
        };
    }

    @Nested
    class Positive {

        @Test
        void basicEnvelopeParses() throws IOException {
            EnvelopeCodec codec = new EnvelopeCodec();
            byte[] bytes = Files.readAllBytes(fixturesDir.resolve("envelopes/basic-1-recipient.cbor"));
            SharedEnvelope env = codec.decode(bytes);
            assertThat(env.version()).isEqualTo(1);
            assertThat(env.issuerLabel()).isEqualTo("Acme Corp");
            assertThat(env.signature()).isNotNull();
            assertThat(env.recipientWrappings()).hasSize(1);
        }

        @Test
        void allPositiveEnvelopesParseAndVerify() throws IOException {
            EnvelopeCodec codec = new EnvelopeCodec();
            EnvelopeVerifier verifier = new EnvelopeVerifier(codec, acmeKeyResolver());

            for (String name : List.of("basic-1-recipient", "three-recipients",
                    "allow-list-update-v2", "unicode-description")) {
                byte[] bytes = Files.readAllBytes(
                        fixturesDir.resolve("envelopes/" + name + ".cbor"));
                SharedEnvelope env = verifier.verify(bytes);
                assertThat(env.version()).as("version for %s", name).isEqualTo(1);
            }
        }

        @Test
        void signedBytesMatchFixtureForAllEnvelopes() throws IOException {
            EnvelopeCodec codec = new EnvelopeCodec();
            for (String name : List.of("basic-1-recipient", "three-recipients",
                    "allow-list-update-v2", "unicode-description")) {
                byte[] envelopeBytes = Files.readAllBytes(
                        fixturesDir.resolve("envelopes/" + name + ".cbor"));
                byte[] expectedSigned = Files.readAllBytes(
                        fixturesDir.resolve("envelopes/" + name + ".signed"));
                SharedEnvelope env = codec.decode(envelopeBytes);
                byte[] signedBytes = codec.signedBytesOf(env.withSignature(null));
                assertThat(signedBytes)
                        .as("signed_bytes for %s", name)
                        .isEqualTo(expectedSigned);
            }
        }

        @Test
        void signatureVerifiesUnderAcmeSignPublicKey() throws IOException {
            EnvelopeCodec codec = new EnvelopeCodec();
            Ed25519.KeyPair acme = acmeSignKeyPair();

            for (String name : List.of("basic-1-recipient", "three-recipients",
                    "allow-list-update-v2", "unicode-description")) {
                byte[] envelopeBytes = Files.readAllBytes(
                        fixturesDir.resolve("envelopes/" + name + ".cbor"));
                SharedEnvelope env = codec.decode(envelopeBytes);
                byte[] signedBytes = codec.signedBytesOf(env.withSignature(null));
                boolean valid = Ed25519.verifyDetached(acme.publicKey(), signedBytes, env.signature());
                assertThat(valid).as("signature valid for %s", name).isTrue();
            }
        }
    }

    @Nested
    class RoundTrip {

        @Test
        void buildBasicEnvelopeFromInputsMatchesFixture() throws IOException {
            JsonNode basicMeta = envelopeMeta.get("basic-1-recipient");
            byte[] dataKey = HEX.parseHex(basicMeta.get("data_key_hex").asText());
            byte[] ctNonce = HEX.parseHex(basicMeta.get("ciphertext_nonce_hex").asText());
            String plaintext = plaintexts.get(basicMeta.get("plaintext_key").asText()).asText();

            byte[] ciphertext = SecretBox.seal(
                    plaintext.getBytes(StandardCharsets.UTF_8), ctNonce, dataKey);
            byte[] ciphertextHash = Sha256.hash(ciphertext);

            byte[] aliceSeed = HEX.parseHex(keypairsInput.get("alice_enc").get("seed_hex").asText());
            X25519.KeyPair aliceKp = X25519.seedKeypair(aliceSeed);

            UUID issuerId = bytesToUuid(HEX.parseHex(directoryMeta.get("issuer_id_hex").asText()));
            UUID entryId = readEntryId("entry_basic");
            byte[] acmeKeyId = HEX.parseHex(directoryMeta.get("key_ids").get("acme_sign").asText());

            UUID aliceVerifierId = bytesToUuid(
                    HEX.parseHex(directoryMeta.get("verifier_ids").get("alice").asText()));
            byte[] aliceKeyId = HEX.parseHex(directoryMeta.get("key_ids").get("alice_enc").asText());

            CanonicalCborMapper cborMapper = new CanonicalCborMapper();
            byte[] existingEnvelope = Files.readAllBytes(
                    fixturesDir.resolve("envelopes/basic-1-recipient.cbor"));
            @SuppressWarnings("unchecked")
            Map<String, Object> existingMap = cborMapper.readValue(existingEnvelope, Map.class);
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> existingWrappings =
                    (List<Map<String, Object>>) existingMap.get("recipient_wrappings");
            byte[] wrappedDataKey = (byte[]) existingWrappings.getFirst().get("wrapped_data_key");

            SharedEnvelope unsigned = new SharedEnvelope(
                    1, entryId, issuerId, "Acme Corp", acmeKeyId,
                    timestamps.get("t_envelope_basic").asLong(),
                    "Basic test credential", "xsalsa20poly1305",
                    ctNonce, ciphertext, ciphertextHash,
                    List.of(new RecipientWrapping(aliceVerifierId, aliceKeyId, wrappedDataKey)),
                    null
            );

            EnvelopeCodec codec = new EnvelopeCodec();
            EnvelopeSigner signer = new EnvelopeSigner(codec);
            Ed25519.KeyPair acme = acmeSignKeyPair();
            byte[] finalBytes = signer.sign(unsigned, acme.privateKey());

            byte[] expected = Files.readAllBytes(
                    fixturesDir.resolve("envelopes/basic-1-recipient.cbor"));
            assertThat(finalBytes).isEqualTo(expected);
        }

        @Test
        void decryptBasicEnvelopeEndToEnd() throws IOException {
            EnvelopeCodec codec = new EnvelopeCodec();
            EnvelopeVerifier verifier = new EnvelopeVerifier(codec, acmeKeyResolver());

            byte[] envelopeBytes = Files.readAllBytes(
                    fixturesDir.resolve("envelopes/basic-1-recipient.cbor"));
            SharedEnvelope env = verifier.verify(envelopeBytes);

            byte[] aliceSeed = HEX.parseHex(keypairsInput.get("alice_enc").get("seed_hex").asText());
            X25519.KeyPair aliceKp = X25519.seedKeypair(aliceSeed);

            byte[] wrappedDataKey = env.recipientWrappings().getFirst().wrappedDataKey();
            byte[] dataKey = com.wilhelmsen.cbslink.plugin.datawallet.crypto.SealedBox.open(
                    wrappedDataKey, aliceKp.publicKey(), aliceKp.secretKey());

            byte[] plaintext = SecretBox.open(env.ciphertext(), env.ciphertextNonce(), dataKey);
            String text = new String(plaintext, StandardCharsets.UTF_8);

            assertThat(text).isEqualTo(plaintexts.get("basic").asText());
        }
    }

    @Nested
    class Negative {

        @Test
        void nonCanonicalCborRejectsMalformedCbor() throws IOException {
            byte[] bytes = Files.readAllBytes(
                    fixturesDir.resolve("envelopes/invalid/non-canonical-cbor.cbor"));
            EnvelopeCodec codec = new EnvelopeCodec();
            assertThatThrownBy(() -> codec.decode(bytes))
                    .isInstanceOf(EnvelopeRejection.MalformedCbor.class);
        }

        @Test
        void futureVersionRejectsUnsupportedVersion() throws IOException {
            byte[] bytes = Files.readAllBytes(
                    fixturesDir.resolve("envelopes/invalid/future-version.cbor"));
            EnvelopeCodec codec = new EnvelopeCodec();
            EnvelopeVerifier verifier = new EnvelopeVerifier(codec, acmeKeyResolver());
            assertThatThrownBy(() -> verifier.verify(bytes))
                    .isInstanceOf(EnvelopeRejection.UnsupportedVersion.class);
        }

        @Test
        void wrongIssuerKeyRejectsSignatureInvalid() throws IOException {
            byte[] bytes = Files.readAllBytes(
                    fixturesDir.resolve("envelopes/invalid/wrong-issuer-key.cbor"));
            EnvelopeCodec codec = new EnvelopeCodec();
            EnvelopeVerifier verifier = new EnvelopeVerifier(codec, acmeKeyResolver());
            assertThatThrownBy(() -> verifier.verify(bytes))
                    .isInstanceOf(EnvelopeRejection.SignatureInvalid.class);
        }

        @Test
        void tamperedCiphertextRejectsSignatureInvalid() throws IOException {
            byte[] bytes = Files.readAllBytes(
                    fixturesDir.resolve("envelopes/invalid/tampered-ciphertext.cbor"));
            EnvelopeCodec codec = new EnvelopeCodec();
            EnvelopeVerifier verifier = new EnvelopeVerifier(codec, acmeKeyResolver());
            assertThatThrownBy(() -> verifier.verify(bytes))
                    .isInstanceOf(EnvelopeRejection.SignatureInvalid.class);
        }

        @Test
        void staleKeyIdRejectsIssuerKeyNotActiveAt() throws IOException {
            byte[] bytes = Files.readAllBytes(
                    fixturesDir.resolve("envelopes/invalid/stale-key-id.cbor"));
            EnvelopeCodec codec = new EnvelopeCodec();
            EnvelopeVerifier verifier = new EnvelopeVerifier(codec, acmeKeyResolver());
            assertThatThrownBy(() -> verifier.verify(bytes))
                    .isInstanceOf(EnvelopeRejection.IssuerKeyNotActiveAt.class);
        }
    }

    @Nested
    class VerificationOrder {

        @Test
        void resolverCalledExactlyOncePerEnvelope() throws IOException {
            EnvelopeCodec codec = new EnvelopeCodec();
            AtomicInteger resolveCount = new AtomicInteger(0);
            Ed25519.KeyPair acme = acmeSignKeyPair();
            byte[] acmeKeyId = HEX.parseHex(directoryMeta.get("key_ids").get("acme_sign").asText());
            UUID issuerId = bytesToUuid(HEX.parseHex(directoryMeta.get("issuer_id_hex").asText()));
            long validFrom = directoryMeta.get("acme_signing_key_valid_from").asLong();
            long validUntil = directoryMeta.get("acme_signing_key_valid_until").asLong();

            IssuerKeyResolver countingResolver = (id, keyId, atMs) -> {
                resolveCount.incrementAndGet();
                if (id.equals(issuerId) && Arrays.equals(keyId, acmeKeyId)) {
                    return Optional.of(new DirectoryKeyView(
                            issuerId, acmeKeyId, acme.publicKey(), "active", validFrom, validUntil
                    ));
                }
                return Optional.empty();
            };

            EnvelopeVerifier verifier = new EnvelopeVerifier(codec, countingResolver);

            byte[] bytes = Files.readAllBytes(
                    fixturesDir.resolve("envelopes/basic-1-recipient.cbor"));
            verifier.verify(bytes);
            assertThat(resolveCount.get())
                    .as("resolver called exactly once per envelope verification")
                    .isEqualTo(1);
        }

        @Test
        void sha256CheckHappensAfterSignatureVerification() throws IOException {
            EnvelopeCodec codec = new EnvelopeCodec();

            byte[] fakeSeed = new byte[32];
            Arrays.fill(fakeSeed, (byte) 0xFF);
            Ed25519.KeyPair fakeKey = Ed25519.seedKeypair(fakeSeed);

            byte[] acmeKeyId = HEX.parseHex(directoryMeta.get("key_ids").get("acme_sign").asText());
            UUID issuerId = bytesToUuid(HEX.parseHex(directoryMeta.get("issuer_id_hex").asText()));
            long validFrom = directoryMeta.get("acme_signing_key_valid_from").asLong();
            long validUntil = directoryMeta.get("acme_signing_key_valid_until").asLong();

            byte[] originalBytes = Files.readAllBytes(
                    fixturesDir.resolve("envelopes/basic-1-recipient.cbor"));
            SharedEnvelope original = codec.decode(originalBytes);

            byte[] tamperedCt = original.ciphertext().clone();
            tamperedCt[0] ^= (byte) 0xFF;
            byte[] tamperedHash = Sha256.hash(tamperedCt);

            SharedEnvelope tamperedUnsigned = new SharedEnvelope(
                    original.version(), original.entryId(), original.issuerId(),
                    original.issuerLabel(), original.issuerSigningKeyId(),
                    original.createdAt(), original.description(),
                    original.ciphertextAlg(), original.ciphertextNonce(),
                    tamperedCt, tamperedHash, original.recipientWrappings(), null
            );
            EnvelopeSigner signer = new EnvelopeSigner(codec);
            byte[] signedWithFakeKey = signer.sign(tamperedUnsigned, fakeKey.privateKey());

            IssuerKeyResolver acmeResolver = (id, keyId, atMs) -> {
                Ed25519.KeyPair acme = acmeSignKeyPair();
                if (id.equals(issuerId) && Arrays.equals(keyId, acmeKeyId)) {
                    return Optional.of(new DirectoryKeyView(
                            issuerId, acmeKeyId, acme.publicKey(), "active", validFrom, validUntil
                    ));
                }
                return Optional.empty();
            };

            EnvelopeVerifier verifier = new EnvelopeVerifier(codec, acmeResolver);
            assertThatThrownBy(() -> verifier.verify(signedWithFakeKey))
                    .isInstanceOf(EnvelopeRejection.SignatureInvalid.class);
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
