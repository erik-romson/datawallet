package com.wilhelmsen.cbslink.plugin.datawallet.envelope;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.Ed25519;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.Random;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.Sha256;
import com.wilhelmsen.cbslink.plugin.datawallet.domain.EntryRecipientRepository;
import com.wilhelmsen.cbslink.plugin.datawallet.domain.EntryRepository;
import com.wilhelmsen.cbslink.plugin.datawallet.persistence.PostgresTestcontainer;
import com.wilhelmsen.cbslink.plugin.datawallet.security.HeaderIssuerPrincipalResolver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/// Security tests proving the `valid_from ≤ created_at < valid_until` lifecycle for issuer signing keys.
///
/// Uses a custom `IssuerKeyResolver` backed by an in-memory registry so the test controls
/// exactly which time windows are advertised. `EnvelopeVerifier` then enforces the range check.
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"test", "it"})
@Import({PostgresTestcontainer.class, HistoricalEnvelopeIT.KeyRegistryConfig.class})
class HistoricalEnvelopeIT {

    // Key validity window used across tests
    static final long T0 = 1_600_000_000_000L;
    static final long T1 = T0 + 86_400_000L * 365L; // T0 + 1 year

    private static UUID acmeIssuerId;
    private static byte[] acmeKeyId;
    private static byte[] acmePublicKey;
    private static byte[] acmePrivateKey;

    @Autowired private MockMvc mvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private EntryRepository entryRepository;
    @Autowired private EntryRecipientRepository entryRecipientRepository;
    @Autowired private JdbcTemplate jdbcTemplate;

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    @TestConfiguration
    static class KeyRegistryConfig {

        /// Thread-safe registry: "issuerId:hex(keyId)" → DirectoryKeyView.
        ///
        /// The resolver returns the view WITHOUT applying time filtering so that
        /// `EnvelopeVerifier`'s own `valid_from ≤ created_at < valid_until` check is exercised.
        static final ConcurrentHashMap<String, DirectoryKeyView> registry = new ConcurrentHashMap<>();

        static void register(UUID issuerId, byte[] keyId, byte[] publicKey, long validFrom, long validUntil) {
            registry.put(registryKey(issuerId, keyId),
                    new DirectoryKeyView(issuerId, keyId, publicKey, "active", validFrom, validUntil));
        }

        static void deregister(UUID issuerId, byte[] keyId) {
            registry.remove(registryKey(issuerId, keyId));
        }

        private static String registryKey(UUID issuerId, byte[] keyId) {
            return issuerId + ":" + HexFormat.of().formatHex(keyId);
        }

        @Bean
        @Primary
        IssuerKeyResolver historyTestKeyResolver() {
            return (issuerId, keyId, atMs) ->
                    Optional.ofNullable(registry.get(registryKey(issuerId, keyId)));
        }
    }

    @BeforeAll
    static void loadAcmeKey() throws IOException {
        Path fixturesDir = resolveFixturesDir();
        ObjectMapper json = new ObjectMapper();
        HexFormat hex = HexFormat.of();

        JsonNode keypairs = json.readTree(fixturesDir.resolve("inputs/keypairs.json").toFile());
        JsonNode meta = json.readTree(fixturesDir.resolve("directory/directory_meta.json").toFile());

        byte[] seed = hex.parseHex(keypairs.get("acme_sign").get("seed_hex").asText());
        Ed25519.KeyPair kp = Ed25519.seedKeypair(seed);
        acmePublicKey = kp.publicKey();
        acmePrivateKey = kp.privateKey();
        acmeKeyId = hex.parseHex(meta.get("key_ids").get("acme_sign").asText());

        byte[] issuerIdBytes = hex.parseHex(meta.get("issuer_id_hex").asText());
        acmeIssuerId = uuidFromBytes(issuerIdBytes);
    }

    @BeforeEach
    void registerAcmeKey() {
        KeyRegistryConfig.register(acmeIssuerId, acmeKeyId, acmePublicKey, T0, T1);
    }

    @AfterEach
    void cleanupEntries() {
        jdbcTemplate.update("DELETE FROM entry_recipients WHERE TRUE");
        jdbcTemplate.update("DELETE FROM entries WHERE TRUE");
        KeyRegistryConfig.registry.clear();
    }

    // --- tests ---

    @Test
    void forgedEnvelope_createdAfterKeyExpiry_isRejected() throws Exception {
        long forgedCreatedAt = T1 + 1; // one millisecond past valid_until
        byte[] envelope = buildAndSign(UUID.randomUUID(), acmeIssuerId, acmeKeyId, acmePrivateKey,
                forgedCreatedAt, List.of());

        mvc.perform(post("/v1/entries")
                        .header(HeaderIssuerPrincipalResolver.HEADER, acmeIssuerId.toString())
                        .contentType("application/cbor")
                        .content(envelope))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error.code").value("issuer_key_not_active"));
    }

    @Test
    void legitimateEnvelope_withinKeyWindow_isAccepted() throws Exception {
        long legitCreatedAt = T1 - 1; // one millisecond before valid_until
        UUID entryId = UUID.randomUUID();
        byte[] envelope = buildAndSign(entryId, acmeIssuerId, acmeKeyId, acmePrivateKey,
                legitCreatedAt, List.of());

        mvc.perform(post("/v1/entries")
                        .header(HeaderIssuerPrincipalResolver.HEADER, acmeIssuerId.toString())
                        .contentType("application/cbor")
                        .content(envelope))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.entry_id").value(entryId.toString()));
    }

    @Test
    void revokedKey_doesNotBlockDownloadOfPreexistingEntry() throws Exception {
        // Ingest a legitimate entry while the key is active
        UUID entryId = UUID.randomUUID();
        UUID verifierId = UUID.randomUUID();
        byte[] verifierKeyId = Random.bytes(16);

        long legitCreatedAt = T1 - 1;
        List<RecipientWrapping> recipients = List.of(
                new RecipientWrapping(verifierId, verifierKeyId, new byte[48])
        );
        byte[] envelope = buildAndSign(entryId, acmeIssuerId, acmeKeyId, acmePrivateKey,
                legitCreatedAt, recipients);

        mvc.perform(post("/v1/entries")
                        .header(HeaderIssuerPrincipalResolver.HEADER, acmeIssuerId.toString())
                        .contentType("application/cbor")
                        .content(envelope))
                .andExpect(status().isCreated());

        // Register verifier and obtain a session token
        String sessionToken = registerAndLogin(verifierId, verifierKeyId);

        // "Revoke" the key: remove it from the resolver registry so no new envelopes can use it
        KeyRegistryConfig.deregister(acmeIssuerId, acmeKeyId);

        // Previously ingested entry must still be downloadable — server does not re-verify
        mvc.perform(get("/v1/shared/" + entryId)
                        .header("Authorization", "Bearer " + sessionToken))
                .andExpect(status().isOk());
    }

    // --- helpers ---

    private byte[] buildAndSign(UUID entryId, UUID issuerId, byte[] issuerKeyId, byte[] issuerPrivKey,
                                 long createdAt, List<RecipientWrapping> recipients) {
        byte[] ciphertext = Random.bytes(32);
        byte[] ciphertextHash = Sha256.hash(ciphertext);
        byte[] nonce = new byte[24];

        SharedEnvelope unsigned = new SharedEnvelope(
                1, entryId, issuerId, "Test Issuer", issuerKeyId,
                createdAt, "historical-test", "xchacha20poly1305",
                nonce, ciphertext, ciphertextHash, recipients, null
        );

        EnvelopeCodec codec = new EnvelopeCodec();
        EnvelopeSigner signer = new EnvelopeSigner(codec);
        return signer.sign(unsigned, issuerPrivKey);
    }

    private String registerAndLogin(UUID verifierId, byte[] authKeyId) throws Exception {
        // Generate an auth keypair so we can produce valid challenge signatures
        byte[] authSeed = Random.bytes(32);
        Ed25519.KeyPair authKp = Ed25519.seedKeypair(authSeed);
        String handle = "hist" + System.nanoTime();

        String regJson = """
                {"handle":"%s","enc_public_key":"%s","enc_key_id":"%s",
                 "auth_public_key":"%s","auth_key_id":"%s",
                 "wrapped_enc_private_key_blob":"%s","wrapped_auth_private_key_blob":"%s",
                 "kdf_salt":"%s","kdf_params":{"alg":"argon2id","m":268435456,"t":3,"p":1,"version":19},
                 "client_password_score":3}
                """.formatted(
                handle,
                B64URL.encodeToString(new byte[32]),
                B64URL.encodeToString(new byte[16]),
                B64URL.encodeToString(authKp.publicKey()),
                B64URL.encodeToString(authKeyId),
                B64URL.encodeToString(new byte[48]),
                B64URL.encodeToString(new byte[48]),
                B64URL.encodeToString(new byte[16])
        );

        MvcResult regResult = mvc.perform(post("/v1/verifiers")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(regJson))
                .andExpect(status().isCreated())
                .andReturn();

        // We registered a new verifier, but we need the PRE-REGISTERED verifierId to match the recipient.
        // Instead, look up the session via the newly registered verifier and then insert the
        // recipient row pointing to that verifier's actual ID.
        UUID registeredVerifierId = UUID.fromString(
                objectMapper.readTree(regResult.getResponse().getContentAsString())
                        .get("verifier_id").asText()
        );

        // Patch the entry_recipients row to use the registered verifier ID
        jdbcTemplate.update(
                "UPDATE entry_recipients SET verifier_id = ?::uuid WHERE verifier_id = ?::uuid",
                registeredVerifierId.toString(), verifierId.toString()
        );

        // Auth challenge + verify
        MvcResult challengeResult = mvc.perform(post("/v1/auth/challenge")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"verifier_id\":\"" + registeredVerifierId + "\"}"))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode challengeBody = objectMapper.readTree(challengeResult.getResponse().getContentAsString());
        String nonce = challengeBody.get("nonce").asText();
        byte[] nonceBytes = Base64.getUrlDecoder().decode(nonce);

        byte[] signedBytes = buildAuthMessage(nonceBytes);
        byte[] sig = Ed25519.signDetached(authKp.privateKey(), signedBytes);

        MvcResult verifyResult = mvc.perform(post("/v1/auth/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"verifier_id":"%s","nonce":"%s","signature":"%s"}
                                """.formatted(registeredVerifierId, nonce, B64URL.encodeToString(sig))))
                .andExpect(status().isOk())
                .andReturn();

        return objectMapper.readTree(verifyResult.getResponse().getContentAsString())
                .get("session_token").asText();
    }

    private static byte[] buildAuthMessage(byte[] nonceBytes) {
        byte[] prefix = "datawallet-auth-v1\0".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] msg = Arrays.copyOf(prefix, prefix.length + nonceBytes.length);
        System.arraycopy(nonceBytes, 0, msg, prefix.length, nonceBytes.length);
        return msg;
    }

    private static UUID uuidFromBytes(byte[] bytes) {
        java.nio.ByteBuffer buf = java.nio.ByteBuffer.wrap(bytes);
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
        throw new IllegalStateException("Could not find spec/fixtures directory");
    }
}
