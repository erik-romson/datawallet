package com.wilhelmsen.cbslink.plugin.datawallet.crypto;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;

class PrimitivesFixtureTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();
    private static Path fixturesDir;

    @BeforeAll
    static void resolveFixtures() {
        fixturesDir = resolveFixturesDir();
    }

    @Nested
    class KekDerivation {

        @Test
        void allPasswordFixturesProduceExpectedKek() throws IOException {
            List<JsonNode> expected = JSON.readValue(
                    fixturesDir.resolve("inputs/passwords.expected.json").toFile(),
                    new TypeReference<>() {}
            );
            for (JsonNode row : expected) {
                String name = row.get("name").asText();
                String password = row.get("password").asText();
                byte[] salt = HEX.parseHex(row.get("kdf_salt_hex").asText());
                JsonNode params = row.get("kdf_params");
                long m = params.get("m").asLong();
                long t = params.get("t").asLong();
                int p = params.get("p").asInt();
                String expectedKekHex = row.get("expected_kek_hex").asText();

                byte[] kek = Argon2id.deriveKek(password, salt, m, t, p);

                assertThat(HEX.formatHex(kek))
                        .as("KEK for %s", name)
                        .isEqualTo(expectedKekHex);
            }
        }

        @Test
        void rejectsParallelismNotOne() {
            byte[] salt = new byte[16];
            assertThatThrownBy(() -> Argon2id.deriveKek("test", salt, 65536, 1, 2))
                    .isInstanceOf(CryptoException.class)
                    .hasMessageContaining("p=1");
        }
    }

    @Nested
    class SecretBoxRoundTrip {

        @Test
        void encryptDecryptRoundTrip() {
            byte[] key = Random.bytes(32);
            byte[] nonce = Random.bytes(24);
            byte[] plaintext = "hello secretbox".getBytes(StandardCharsets.UTF_8);

            byte[] ciphertext = SecretBox.seal(plaintext, nonce, key);
            byte[] recovered = SecretBox.open(ciphertext, nonce, key);

            assertThat(recovered).isEqualTo(plaintext);
        }

        @Test
        void wrongKeyFailsToDecrypt() {
            byte[] key = Random.bytes(32);
            byte[] wrongKey = Random.bytes(32);
            byte[] nonce = Random.bytes(24);
            byte[] plaintext = "test".getBytes(StandardCharsets.UTF_8);

            byte[] ciphertext = SecretBox.seal(plaintext, nonce, key);

            assertThatThrownBy(() -> SecretBox.open(ciphertext, nonce, wrongKey))
                    .isInstanceOf(CryptoException.class);
        }
    }

    @Nested
    class SealedBoxOpen {

        @Test
        void sealAndOpenRoundTrip() throws IOException {
            JsonNode keypairs = JSON.readTree(fixturesDir.resolve("inputs/keypairs.json").toFile());
            byte[] seed = HEX.parseHex(keypairs.get("alice_enc").get("seed_hex").asText());
            X25519.KeyPair kp = X25519.seedKeypair(seed);

            byte[] plaintext = "sealed box test".getBytes(StandardCharsets.UTF_8);
            byte[] ciphertext = SealedBox.seal(plaintext, kp.publicKey());
            byte[] recovered = SealedBox.open(ciphertext, kp.publicKey(), kp.secretKey());

            assertThat(recovered).isEqualTo(plaintext);
        }

        @Test
        void openWrappedDataKeyFromFixture() throws IOException {
            JsonNode keypairs = JSON.readTree(fixturesDir.resolve("inputs/keypairs.json").toFile());
            byte[] aliceSeed = HEX.parseHex(keypairs.get("alice_enc").get("seed_hex").asText());
            X25519.KeyPair aliceKp = X25519.seedKeypair(aliceSeed);

            JsonNode envelopeMeta = JSON.readTree(fixturesDir.resolve("envelopes/envelope_meta.json").toFile());
            JsonNode basicMeta = envelopeMeta.get("basic-1-recipient");
            byte[] expectedDataKey = HEX.parseHex(basicMeta.get("data_key_hex").asText());

            CanonicalCborMapper cbor = new CanonicalCborMapper();
            byte[] envelopeBytes = Files.readAllBytes(fixturesDir.resolve("envelopes/basic-1-recipient.cbor"));
            @SuppressWarnings("unchecked")
            Map<String, Object> envelope = cbor.readValue(envelopeBytes, Map.class);
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> wrappings = (List<Map<String, Object>>) envelope.get("recipient_wrappings");
            byte[] wrappedDataKey = (byte[]) wrappings.getFirst().get("wrapped_data_key");

            byte[] dataKey = SealedBox.open(wrappedDataKey, aliceKp.publicKey(), aliceKp.secretKey());
            assertThat(dataKey).isEqualTo(expectedDataKey);
        }
    }

    @Nested
    class Ed25519Determinism {

        @Test
        void seedKeypairMatchesExpectedPublicKeys() throws IOException {
            JsonNode keypairs = JSON.readTree(fixturesDir.resolve("inputs/keypairs.json").toFile());
            JsonNode expected = JSON.readTree(fixturesDir.resolve("inputs/keypairs.expected.json").toFile());

            var it = keypairs.fields();
            while (it.hasNext()) {
                var entry = it.next();
                String name = entry.getKey();
                String type = entry.getValue().get("type").asText();
                if (!"ed25519".equals(type)) continue;

                byte[] seed = HEX.parseHex(entry.getValue().get("seed_hex").asText());
                Ed25519.KeyPair kp = Ed25519.seedKeypair(seed);
                String expectedPubHex = expected.get(name).get("public_key_hex").asText();

                assertThat(HEX.formatHex(kp.publicKey()))
                        .as("Ed25519 public key for %s", name)
                        .isEqualTo(expectedPubHex);
            }
        }

        @Test
        void x25519SeedKeypairMatchesExpectedPublicKeys() throws IOException {
            JsonNode keypairs = JSON.readTree(fixturesDir.resolve("inputs/keypairs.json").toFile());
            JsonNode expected = JSON.readTree(fixturesDir.resolve("inputs/keypairs.expected.json").toFile());

            var it = keypairs.fields();
            while (it.hasNext()) {
                var entry = it.next();
                String name = entry.getKey();
                String type = entry.getValue().get("type").asText();
                if (!"x25519".equals(type)) continue;

                byte[] seed = HEX.parseHex(entry.getValue().get("seed_hex").asText());
                X25519.KeyPair kp = X25519.seedKeypair(seed);
                String expectedPubHex = expected.get(name).get("public_key_hex").asText();

                assertThat(HEX.formatHex(kp.publicKey()))
                        .as("X25519 public key for %s", name)
                        .isEqualTo(expectedPubHex);
            }
        }

        @Test
        void authSignatureMatchesFixture() throws IOException {
            JsonNode authFixture = JSON.readTree(fixturesDir.resolve("auth/nonce-and-signature.json").toFile());
            JsonNode keypairs = JSON.readTree(fixturesDir.resolve("inputs/keypairs.json").toFile());

            String signerName = authFixture.get("signer").asText();
            byte[] seed = HEX.parseHex(keypairs.get(signerName).get("seed_hex").asText());
            Ed25519.KeyPair kp = Ed25519.seedKeypair(seed);

            byte[] nonce = HEX.parseHex(authFixture.get("nonce_hex").asText());
            byte[] prefix = HEX.parseHex(authFixture.get("prefix_hex").asText());
            byte[] expectedSignedBytes = HEX.parseHex(authFixture.get("expected_signed_bytes_hex").asText());
            byte[] expectedSig = HEX.parseHex(authFixture.get("expected_sig_hex").asText());

            byte[] signedBytes = new byte[prefix.length + nonce.length];
            System.arraycopy(prefix, 0, signedBytes, 0, prefix.length);
            System.arraycopy(nonce, 0, signedBytes, prefix.length, nonce.length);
            assertThat(signedBytes).isEqualTo(expectedSignedBytes);

            byte[] signature = Ed25519.signDetached(kp.privateKey(), signedBytes);
            assertThat(HEX.formatHex(signature))
                    .isEqualTo(authFixture.get("expected_sig_hex").asText());

            assertThat(Ed25519.verifyDetached(kp.publicKey(), signedBytes, signature)).isTrue();
        }

        @Test
        void verifyDetachedRejectsFlippedBit() throws IOException {
            JsonNode authFixture = JSON.readTree(fixturesDir.resolve("auth/nonce-and-signature.json").toFile());
            byte[] expectedSig = HEX.parseHex(authFixture.get("expected_sig_hex").asText());
            byte[] signedBytes = HEX.parseHex(authFixture.get("expected_signed_bytes_hex").asText());
            byte[] pubKey = HEX.parseHex(authFixture.get("signer_public_key_hex").asText());

            byte[] tamperedSig = Arrays.copyOf(expectedSig, expectedSig.length);
            tamperedSig[0] ^= 0x01;

            assertThat(Ed25519.verifyDetached(pubKey, signedBytes, tamperedSig)).isFalse();
        }
    }

    @Nested
    class Sha256Vectors {

        @Test
        void emptyStringHash() {
            byte[] hash = Sha256.hash(new byte[0]);
            assertThat(HEX.formatHex(hash))
                    .isEqualTo("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        }

        @Test
        void abcHash() {
            byte[] hash = Sha256.hash("abc".getBytes(StandardCharsets.UTF_8));
            assertThat(HEX.formatHex(hash))
                    .isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        }

        @Test
        void envelopeCiphertextHashMatchesFixture() throws IOException {
            CanonicalCborMapper cbor = new CanonicalCborMapper();
            byte[] envelopeBytes = Files.readAllBytes(fixturesDir.resolve("envelopes/basic-1-recipient.cbor"));
            @SuppressWarnings("unchecked")
            Map<String, Object> envelope = cbor.readValue(envelopeBytes, Map.class);

            byte[] ciphertext = (byte[]) envelope.get("ciphertext");
            byte[] ciphertextHash = (byte[]) envelope.get("ciphertext_hash");

            byte[] computed = Sha256.hash(ciphertext);
            assertThat(computed).isEqualTo(ciphertextHash);
        }
    }

    @Nested
    class UuidV7Vectors {

        @Test
        void allFixtureUuidsMatch() throws IOException {
            List<JsonNode> uuids = JSON.readValue(
                    fixturesDir.resolve("inputs/uuids.expected.json").toFile(),
                    new TypeReference<>() {}
            );
            for (JsonNode row : uuids) {
                String name = row.get("name").asText();
                long tsMs = row.get("ts_ms").asLong();
                byte[] fullRand = HEX.parseHex(row.get("rand_hex").asText());
                byte[] rand10 = Arrays.copyOf(fullRand, 10);
                String expectedHex = row.get("expected_hex").asText();

                UUID uuid = UuidV7.generate(tsMs, rand10);
                String actualHex = HEX.formatHex(uuidToBytes(uuid));

                assertThat(actualHex)
                        .as("UUIDv7 for %s", name)
                        .isEqualTo(expectedHex);
            }
        }

        @Test
        void generatedUuidHasVersion7AndRfcVariant() {
            UUID uuid = UuidV7.now();
            assertThat(uuid.version()).isEqualTo(7);
            assertThat(uuid.variant()).isEqualTo(2);
        }
    }

    @Nested
    class FingerprintVectors {

        @Test
        void allFixtureFingerprintsMatch() throws IOException {
            List<JsonNode> fingerprints = JSON.readValue(
                    fixturesDir.resolve("fingerprints/pubkey-to-fp.json").toFile(),
                    new TypeReference<>() {}
            );
            for (JsonNode row : fingerprints) {
                String name = row.get("name").asText();
                byte[] pubKey = HEX.parseHex(row.get("public_key_hex").asText());
                String expectedRender = row.get("expected_fp_render").asText();

                String actual = Fingerprint.render(pubKey);

                assertThat(actual)
                        .as("Fingerprint for %s", name)
                        .isEqualTo(expectedRender);
            }
        }
    }

    @Nested
    class NoDirectLazySodiumUsage {

        @Test
        void noCodeOutsideCryptoPackageUsesLazySodiumDirectly() throws IOException {
            Path srcMain = fixturesDir.getParent().getParent().resolve("src/main/java");
            if (!Files.isDirectory(srcMain)) {
                fail("Could not find src/main/java from fixtures dir");
            }
            try (var stream = Files.walk(srcMain)) {
                List<Path> violations = stream
                        .filter(p -> p.toString().endsWith(".java"))
                        .filter(p -> !p.toString().contains("/crypto/"))
                        .filter(p -> {
                            try {
                                String content = Files.readString(p);
                                return content.contains("LazySodium")
                                        || content.contains("SodiumJava")
                                        || content.contains("com.goterl.lazysodium");
                            } catch (IOException e) {
                                return false;
                            }
                        })
                        .toList();
                assertThat(violations)
                        .as("Files outside crypto/ that reference LazySodium directly")
                        .isEmpty();
            }
        }

        @Test
        void noSecureRandomInMainSources() throws IOException {
            Path srcMain = fixturesDir.getParent().getParent().resolve("src/main/java");
            if (!Files.isDirectory(srcMain)) {
                fail("Could not find src/main/java from fixtures dir");
            }
            try (var stream = Files.walk(srcMain)) {
                List<Path> violations = stream
                        .filter(p -> p.toString().endsWith(".java"))
                        .filter(p -> {
                            try {
                                return Files.readString(p).contains("SecureRandom");
                            } catch (IOException e) {
                                return false;
                            }
                        })
                        .toList();
                assertThat(violations)
                        .as("Files that reference SecureRandom")
                        .isEmpty();
            }
        }
    }

    private static byte[] uuidToBytes(UUID uuid) {
        byte[] bytes = new byte[16];
        long msb = uuid.getMostSignificantBits();
        long lsb = uuid.getLeastSignificantBits();
        for (int i = 0; i < 8; i++) {
            bytes[i] = (byte) (msb >>> (56 - i * 8));
            bytes[8 + i] = (byte) (lsb >>> (56 - i * 8));
        }
        return bytes;
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
