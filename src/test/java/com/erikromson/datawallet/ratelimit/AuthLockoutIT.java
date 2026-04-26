package com.erikromson.datawallet.ratelimit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.erikromson.datawallet.api.auth.AuthController;
import com.erikromson.datawallet.crypto.Ed25519;
import com.erikromson.datawallet.crypto.Random;
import com.erikromson.datawallet.persistence.PostgresTestcontainer;
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

import java.util.Base64;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(PostgresTestcontainer.class)
class AuthLockoutIT {

    @Autowired private MockMvc mvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private JdbcTemplate jdbcTemplate;

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();

    @BeforeEach
    void resetLockouts() {
        jdbcTemplate.update("DELETE FROM auth_lockouts");
        jdbcTemplate.update("DELETE FROM rate_limits");
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static String b64(int len) {
        byte[] b = new byte[len];
        java.util.Arrays.fill(b, (byte) 0x42);
        return B64URL.encodeToString(b);
    }

    private record RegisteredVerifier(UUID verifierId, Ed25519.KeyPair kp) {}

    private RegisteredVerifier registerVerifier() throws Exception {
        byte[] seed = Random.bytes(32);
        Ed25519.KeyPair kp = Ed25519.seedKeypair(seed);
        String handle = "lo" + System.nanoTime();

        String json = """
                {
                  "handle": "%s",
                  "display_name": "Lockout Test",
                  "enc_public_key": "%s",
                  "enc_key_id": "%s",
                  "auth_public_key": "%s",
                  "auth_key_id": "%s",
                  "wrapped_enc_private_key_blob": "%s",
                  "wrapped_auth_private_key_blob": "%s",
                  "kdf_salt": "%s",
                  "kdf_params": {"alg":"argon2id","m":268435456,"t":3,"p":1,"version":19},
                  "client_password_score": 3
                }
                """.formatted(handle, b64(32), b64(16),
                B64URL.encodeToString(kp.publicKey()), b64(16),
                b64(48), b64(48), b64(16));

        MvcResult reg = mvc.perform(post("/v1/verifiers")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isCreated())
                .andReturn();

        JsonNode body = objectMapper.readTree(reg.getResponse().getContentAsString());
        return new RegisteredVerifier(UUID.fromString(body.get("verifier_id").asText()), kp);
    }

    private String requestChallenge(UUID verifierId) throws Exception {
        String body = """
                {"verifier_id": "%s"}
                """.formatted(verifierId);
        MvcResult result = mvc.perform(post("/v1/auth/challenge")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString()).get("nonce").asText();
    }

    private void sendInvalidVerify(UUID verifierId, String nonce) throws Exception {
        // reset rate-limit bucket so the lockout test never trips the rate limiter
        jdbcTemplate.update("DELETE FROM rate_limits");

        byte[] wrongSeed = Random.bytes(32);
        Ed25519.KeyPair wrongKp = Ed25519.seedKeypair(wrongSeed);
        byte[] nonceBytes = B64URL_DEC.decode(nonce);
        byte[] sig = Ed25519.signDetached(wrongKp.privateKey(), AuthController.buildSignedBytes(nonceBytes));

        String body = """
                {"verifier_id": "%s", "nonce": "%s", "signature": "%s"}
                """.formatted(verifierId, nonce, B64URL.encodeToString(sig));

        mvc.perform(post("/v1/auth/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("auth_invalid_signature"));
    }

    private String sendValidVerify(UUID verifierId, Ed25519.KeyPair kp, String nonce) throws Exception {
        jdbcTemplate.update("DELETE FROM rate_limits");

        byte[] nonceBytes = B64URL_DEC.decode(nonce);
        byte[] sig = Ed25519.signDetached(kp.privateKey(), AuthController.buildSignedBytes(nonceBytes));

        String body = """
                {"verifier_id": "%s", "nonce": "%s", "signature": "%s"}
                """.formatted(verifierId, nonce, B64URL.encodeToString(sig));

        MvcResult result = mvc.perform(post("/v1/auth/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn();

        return objectMapper.readTree(result.getResponse().getContentAsString()).get("session_token").asText();
    }

    // ── tests ────────────────────────────────────────────────────────────────

    @Test
    void tenConsecutiveFailures_locksAccount_eleventhReturns423() throws Exception {
        RegisteredVerifier v = registerVerifier();
        String nonce = requestChallenge(v.verifierId());

        // 10 consecutive invalid verifies — nonce not consumed on failure, so reuse same nonce
        for (int i = 0; i < 10; i++) {
            sendInvalidVerify(v.verifierId(), nonce);
        }

        // 11th attempt: account is now locked — reset rate limits first so the interceptor lets it through
        jdbcTemplate.update("DELETE FROM rate_limits");
        byte[] wrongSeed = Random.bytes(32);
        Ed25519.KeyPair wrongKp = Ed25519.seedKeypair(wrongSeed);
        byte[] nonceBytes = B64URL_DEC.decode(nonce);
        byte[] sig = Ed25519.signDetached(wrongKp.privateKey(), AuthController.buildSignedBytes(nonceBytes));

        String verifyBody = """
                {"verifier_id": "%s", "nonce": "%s", "signature": "%s"}
                """.formatted(v.verifierId(), nonce, B64URL.encodeToString(sig));

        mvc.perform(post("/v1/auth/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(verifyBody))
                .andExpect(status().is(423))
                .andExpect(header().exists("Retry-After"))
                .andExpect(jsonPath("$.error.code").value("auth_locked"));
    }

    @Test
    void successfulVerify_beforeTenth_resetsCounter() throws Exception {
        RegisteredVerifier v = registerVerifier();
        String nonce = requestChallenge(v.verifierId());

        // 9 invalid verifies (one short of lockout threshold)
        for (int i = 0; i < 9; i++) {
            sendInvalidVerify(v.verifierId(), nonce);
        }

        // valid verify resets the counter (nonce is still unconsumed since all verifies failed)
        sendValidVerify(v.verifierId(), v.kp(), nonce);

        // after reset: one more invalid verify should return 401, not 423
        jdbcTemplate.update("DELETE FROM rate_limits");
        String nonce2 = requestChallenge(v.verifierId());
        jdbcTemplate.update("DELETE FROM rate_limits");
        byte[] wrongSeed = Random.bytes(32);
        Ed25519.KeyPair wrongKp = Ed25519.seedKeypair(wrongSeed);
        byte[] nonceBytes2 = B64URL_DEC.decode(nonce2);
        byte[] sig = Ed25519.signDetached(wrongKp.privateKey(), AuthController.buildSignedBytes(nonceBytes2));

        String verifyBody = """
                {"verifier_id": "%s", "nonce": "%s", "signature": "%s"}
                """.formatted(v.verifierId(), nonce2, B64URL.encodeToString(sig));

        mvc.perform(post("/v1/auth/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(verifyBody))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("auth_invalid_signature"));
    }
}
