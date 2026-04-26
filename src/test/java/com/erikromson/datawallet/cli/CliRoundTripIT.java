package com.erikromson.datawallet.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.erikromson.datawallet.api.entry.FixtureIssuerKeyResolver;
import com.erikromson.datawallet.crypto.CanonicalCborMapper;
import com.erikromson.datawallet.crypto.Ed25519;
import com.erikromson.datawallet.crypto.UuidV7;
import com.erikromson.datawallet.crypto.X25519;
import com.erikromson.datawallet.directory.DirectoryRecordCodec;
import com.erikromson.datawallet.directory.PinnedRoot;
import com.erikromson.datawallet.directory.RootUpdateCodec;
import com.erikromson.datawallet.persistence.PostgresTestcontainer;
import com.erikromson.datawallet.security.HeaderIssuerPrincipalResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"test", "it"})
@Import({PostgresTestcontainer.class, FixtureIssuerKeyResolver.class})
class CliRoundTripIT {

    private static final HexFormat HEX = HexFormat.of();
    private static final java.util.Base64.Encoder B64 = java.util.Base64.getUrlEncoder().withoutPadding();
    private static final java.util.Base64.Decoder B64_DEC = java.util.Base64.getUrlDecoder();

    // Fixture constants from spec/fixtures/inputs/keypairs.json + directory/directory_meta.json
    private static final String ACME_SIGN_SEED =
            "0505050505050505050505050505050505050505050505050505050505050505";
    private static final String ACME_KEY_ID_HEX = "f849d67325facf04177bc663b2dc5440";
    private static final String ACME_ISSUER_UUID = "01941f29-7c00-7050-9050-505050505050";

    private static final String ALICE_ENC_SEED =
            "0101010101010101010101010101010101010101010101010101010101010101";
    private static final String ALICE_AUTH_SEED =
            "0202020202020202020202020202020202020202020202020202020202020202";
    private static final String ALICE_ENC_KEY_ID_HEX = "72cd6e8422c407fb6d098690f1130b7d";
    private static final String ALICE_AUTH_KEY_ID_HEX = "75877bb41d393b5fb8455ce60ecd8dda";

    @Autowired private MockMvc mvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private JdbcTemplate jdbcTemplate;

    private UUID aliceId;
    private String aliceBearer;
    private X25519.KeyPair aliceEncKp;

    @BeforeEach
    void registerAliceAndCleanupEntries() throws Exception {
        jdbcTemplate.update("DELETE FROM entry_recipients WHERE entry_id IN " +
                "(SELECT entry_id FROM entries WHERE issuer_id = ?::uuid)", ACME_ISSUER_UUID);
        jdbcTemplate.update("DELETE FROM entries WHERE issuer_id = ?::uuid", ACME_ISSUER_UUID);

        byte[] aliceEncSeed = HEX.parseHex(ALICE_ENC_SEED);
        aliceEncKp = X25519.seedKeypair(aliceEncSeed);

        byte[] aliceAuthSeed = HEX.parseHex(ALICE_AUTH_SEED);
        Ed25519.KeyPair aliceAuthKp = Ed25519.seedKeypair(aliceAuthSeed);

        byte[] aliceEncKeyId = HEX.parseHex(ALICE_ENC_KEY_ID_HEX);
        byte[] aliceAuthKeyId = HEX.parseHex(ALICE_AUTH_KEY_ID_HEX);

        String handle = "cli-alice-" + (System.nanoTime() % 1_000_000);
        String regJson = """
                {"handle":"%s","display_name":"Alice","enc_public_key":"%s","enc_key_id":"%s",
                "auth_public_key":"%s","auth_key_id":"%s",
                "wrapped_enc_private_key_blob":"%s","wrapped_auth_private_key_blob":"%s",
                "kdf_salt":"%s","kdf_params":{"alg":"argon2id","m":268435456,"t":3,"p":1,"version":19},
                "client_password_score":3}
                """.formatted(
                handle,
                B64.encodeToString(aliceEncKp.publicKey()), B64.encodeToString(aliceEncKeyId),
                B64.encodeToString(aliceAuthKp.publicKey()), B64.encodeToString(aliceAuthKeyId),
                B64.encodeToString(new byte[48]), B64.encodeToString(new byte[48]),
                B64.encodeToString(new byte[16])
        );

        MvcResult regResult = mvc.perform(post("/v1/verifiers")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(regJson))
                .andExpect(status().isCreated())
                .andReturn();

        aliceId = UUID.fromString(objectMapper
                .readTree(regResult.getResponse().getContentAsString())
                .get("verifier_id").asText());

        aliceBearer = authenticate(aliceId, aliceAuthKp.privateKey());
    }

    @Test
    void buildEnvelopeRoundTrip() throws Exception {
        byte[] acmeSeed = HEX.parseHex(ACME_SIGN_SEED);
        Ed25519.KeyPair acmeKp = Ed25519.seedKeypair(acmeSeed);
        byte[] acmeKeyId = HEX.parseHex(ACME_KEY_ID_HEX);
        UUID issuerId = UUID.fromString(ACME_ISSUER_UUID);
        UUID entryId = UuidV7.now();

        byte[] aliceEncKeyId = HEX.parseHex(ALICE_ENC_KEY_ID_HEX);

        // Use a timestamp within the fixture key's validity window (Jan 2025, before valid_until Jan 2026)
        long createdAt = 1740000000000L; // 2025-02-20T00:00:00Z

        byte[] envelopeBytes = BuildEnvelopeCommand.buildEnvelope(
                "CLI round-trip test credential",
                entryId,
                issuerId,
                "Acme Corp",
                acmeKeyId,
                acmeKp.privateKey(),
                createdAt,
                "CLI round-trip test",
                List.of(new BuildEnvelopeCommand.RecipientInfo(aliceId, aliceEncKeyId, aliceEncKp.publicKey()))
        );

        mvc.perform(post("/v1/entries")
                        .contentType("application/cbor")
                        .header(HeaderIssuerPrincipalResolver.HEADER, ACME_ISSUER_UUID)
                        .content(envelopeBytes))
                .andExpect(status().isCreated());

        MvcResult getResult = mvc.perform(get("/v1/shared/" + entryId)
                        .header("Authorization", "Bearer " + aliceBearer))
                .andExpect(status().isOk())
                .andReturn();

        byte[] returned = getResult.getResponse().getContentAsByteArray();
        assertThat(returned).isEqualTo(envelopeBytes);
    }

    @Test
    void genRootPinnedRootCanonicalRoundTrip() {
        GenRootCommand.Result result = GenRootCommand.generate(3, 2);

        assertThat(result.pinnedRoot().threshold()).isEqualTo(2);
        assertThat(result.pinnedRoot().roots()).hasSize(3);

        RootUpdateCodec updateCodec = new RootUpdateCodec();
        byte[] pinnedRootBytes = updateCodec.encodePinnedRoot(result.pinnedRoot());

        DirectoryRecordCodec dirCodec = new DirectoryRecordCodec();
        PinnedRoot decoded = dirCodec.decodePinnedRoot(pinnedRootBytes);
        assertThat(decoded.threshold()).isEqualTo(2);
        assertThat(decoded.roots()).hasSize(3);

        // Re-encoding must be identity (canonical CBOR check)
        CanonicalCborMapper cbor = new CanonicalCborMapper();
        byte[] reencoded = cbor.reencode(pinnedRootBytes);
        assertThat(reencoded).isEqualTo(pinnedRootBytes);
    }

    // --- helpers ---

    private String authenticate(UUID verifierId, byte[] authPrivKey) throws Exception {
        MvcResult challengeResult = mvc.perform(post("/v1/auth/challenge")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"verifier_id\":\"" + verifierId + "\"}"))
                .andReturn();

        String nonceB64 = objectMapper
                .readTree(challengeResult.getResponse().getContentAsString())
                .get("nonce").asText();

        byte[] nonceBytes = B64_DEC.decode(nonceB64);
        byte[] prefix = "datawallet-auth-v1\0".getBytes(StandardCharsets.US_ASCII);
        byte[] signedBytes = new byte[prefix.length + nonceBytes.length];
        System.arraycopy(prefix, 0, signedBytes, 0, prefix.length);
        System.arraycopy(nonceBytes, 0, signedBytes, prefix.length, nonceBytes.length);
        byte[] sig = Ed25519.signDetached(authPrivKey, signedBytes);

        MvcResult verifyResult = mvc.perform(post("/v1/auth/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"verifier_id\":\"" + verifierId
                                + "\",\"nonce\":\"" + nonceB64
                                + "\",\"signature\":\"" + B64.encodeToString(sig) + "\"}"))
                .andReturn();

        return objectMapper
                .readTree(verifyResult.getResponse().getContentAsString())
                .get("session_token").asText();
    }
}
