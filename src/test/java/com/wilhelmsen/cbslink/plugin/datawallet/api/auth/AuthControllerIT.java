package com.wilhelmsen.cbslink.plugin.datawallet.api.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.Ed25519;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.Random;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.Sha256;
import com.wilhelmsen.cbslink.plugin.datawallet.domain.AuthChallengeEntity;
import com.wilhelmsen.cbslink.plugin.datawallet.domain.AuthChallengeRepository;
import com.wilhelmsen.cbslink.plugin.datawallet.domain.SessionRepository;
import com.wilhelmsen.cbslink.plugin.datawallet.persistence.PostgresTestcontainer;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(PostgresTestcontainer.class)
class AuthControllerIT {

    @Autowired private MockMvc mvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private AuthChallengeRepository challengeRepository;
    @Autowired private SessionRepository sessionRepository;

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();

    private static String b64(int len) {
        byte[] b = new byte[len];
        java.util.Arrays.fill(b, (byte) 0x42);
        return B64URL.encodeToString(b);
    }

    private record RegisteredVerifier(UUID verifierId, Ed25519.KeyPair authKeyPair) {}

    private RegisteredVerifier registerVerifier() throws Exception {
        byte[] seed = Random.bytes(32);
        Ed25519.KeyPair kp = Ed25519.seedKeypair(seed);
        String handle = "auth" + System.nanoTime();

        String json = """
                {
                  "handle": "%s",
                  "display_name": "Test User",
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
        UUID verifierId = UUID.fromString(body.get("verifier_id").asText());
        return new RegisteredVerifier(verifierId, kp);
    }

    private String requestChallenge(UUID verifierId) throws Exception {
        String body = """
                {"verifier_id": "%s"}
                """.formatted(verifierId);

        MvcResult result = mvc.perform(post("/v1/auth/challenge")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.nonce").exists())
                .andExpect(jsonPath("$.expires_at").exists())
                .andReturn();

        JsonNode json = objectMapper.readTree(result.getResponse().getContentAsString());
        return json.get("nonce").asText();
    }

    private String authenticate(UUID verifierId, Ed25519.KeyPair kp, String nonceB64) throws Exception {
        byte[] nonceBytes = B64URL_DEC.decode(nonceB64);
        byte[] signedBytes = AuthController.buildSignedBytes(nonceBytes);
        byte[] sig = Ed25519.signDetached(kp.privateKey(), signedBytes);

        String verifyBody = """
                {"verifier_id": "%s", "nonce": "%s", "signature": "%s"}
                """.formatted(verifierId, nonceB64, B64URL.encodeToString(sig));

        MvcResult result = mvc.perform(post("/v1/auth/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(verifyBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.session_token").exists())
                .andExpect(jsonPath("$.expires_at").exists())
                .andReturn();

        JsonNode json = objectMapper.readTree(result.getResponse().getContentAsString());
        return json.get("session_token").asText();
    }

    @Nested
    class HappyPath {

        @Test
        void challengeVerifyAndUseBearer() throws Exception {
            var v = registerVerifier();
            String nonceB64 = requestChallenge(v.verifierId());
            String sessionToken = authenticate(v.verifierId(), v.authKeyPair(), nonceB64);

            mvc.perform(post("/v1/auth/logout")
                            .header("Authorization", "Bearer " + sessionToken))
                    .andExpect(status().isNoContent());
        }

        @Test
        void sessionTokenStoredAsHash() throws Exception {
            var v = registerVerifier();
            String nonceB64 = requestChallenge(v.verifierId());
            String sessionToken = authenticate(v.verifierId(), v.authKeyPair(), nonceB64);

            byte[] tokenBytes = B64URL_DEC.decode(sessionToken);
            byte[] expectedTokenId = Sha256.hash(tokenBytes);

            assertThat(sessionRepository.findByTokenId(expectedTokenId)).isPresent();
        }

        @Test
        void consumedNoncesAreKeptNotDeleted() throws Exception {
            var v = registerVerifier();
            String nonceB64 = requestChallenge(v.verifierId());
            authenticate(v.verifierId(), v.authKeyPair(), nonceB64);

            byte[] nonceBytes = B64URL_DEC.decode(nonceB64);
            var pk = new AuthChallengeEntity.PK(v.verifierId(), nonceBytes);
            var challenge = challengeRepository.findById(pk);
            assertThat(challenge).isPresent();
            assertThat(challenge.get().getConsumedAt()).isNotNull();
        }
    }

    @Nested
    class Negative {

        @Test
        void replayConsumedNonce401() throws Exception {
            var v = registerVerifier();
            String nonceB64 = requestChallenge(v.verifierId());
            authenticate(v.verifierId(), v.authKeyPair(), nonceB64);

            byte[] nonceBytes = B64URL_DEC.decode(nonceB64);
            byte[] signedBytes = AuthController.buildSignedBytes(nonceBytes);
            byte[] sig = Ed25519.signDetached(v.authKeyPair().privateKey(), signedBytes);

            String verifyBody = """
                    {"verifier_id": "%s", "nonce": "%s", "signature": "%s"}
                    """.formatted(v.verifierId(), nonceB64, B64URL.encodeToString(sig));

            mvc.perform(post("/v1/auth/verify")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(verifyBody))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error.code").value("auth_nonce_consumed"));
        }

        @Test
        void expiredNonce401() throws Exception {
            var v = registerVerifier();
            String nonceB64 = requestChallenge(v.verifierId());

            byte[] nonceBytes = B64URL_DEC.decode(nonceB64);
            var pk = new AuthChallengeEntity.PK(v.verifierId(), nonceBytes);
            var challenge = challengeRepository.findById(pk).orElseThrow();
            challenge.setConsumedAt(null);
            var expired = new AuthChallengeEntity(
                    v.verifierId(), nonceBytes, challenge.getCreatedAt(), Instant.now().minusSeconds(1)
            );
            challengeRepository.delete(challenge);
            challengeRepository.saveAndFlush(expired);

            byte[] signedBytes = AuthController.buildSignedBytes(nonceBytes);
            byte[] sig = Ed25519.signDetached(v.authKeyPair().privateKey(), signedBytes);

            String verifyBody = """
                    {"verifier_id": "%s", "nonce": "%s", "signature": "%s"}
                    """.formatted(v.verifierId(), nonceB64, B64URL.encodeToString(sig));

            mvc.perform(post("/v1/auth/verify")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(verifyBody))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error.code").value("auth_nonce_expired"));
        }

        @Test
        void wrongSignature401() throws Exception {
            var v = registerVerifier();
            String nonceB64 = requestChallenge(v.verifierId());

            byte[] wrongSeed = Random.bytes(32);
            Ed25519.KeyPair wrongKp = Ed25519.seedKeypair(wrongSeed);
            byte[] nonceBytes = B64URL_DEC.decode(nonceB64);
            byte[] signedBytes = AuthController.buildSignedBytes(nonceBytes);
            byte[] sig = Ed25519.signDetached(wrongKp.privateKey(), signedBytes);

            String verifyBody = """
                    {"verifier_id": "%s", "nonce": "%s", "signature": "%s"}
                    """.formatted(v.verifierId(), nonceB64, B64URL.encodeToString(sig));

            mvc.perform(post("/v1/auth/verify")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(verifyBody))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error.code").value("auth_invalid_signature"));
        }

        @Test
        void unknownVerifierId404() throws Exception {
            UUID fakeId = UUID.randomUUID();
            String body = """
                    {"verifier_id": "%s"}
                    """.formatted(fakeId);

            mvc.perform(post("/v1/auth/challenge")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(body))
                    .andExpect(status().isNotFound())
                    .andExpect(jsonPath("$.error.code").value("verifier_not_found"));
        }

        @Test
        void logoutInvalidatesBearer() throws Exception {
            var v = registerVerifier();
            String nonceB64 = requestChallenge(v.verifierId());
            String sessionToken = authenticate(v.verifierId(), v.authKeyPair(), nonceB64);

            mvc.perform(post("/v1/auth/logout")
                            .header("Authorization", "Bearer " + sessionToken))
                    .andExpect(status().isNoContent());

            mvc.perform(post("/v1/auth/logout")
                            .header("Authorization", "Bearer " + sessionToken))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        void invalidBase64Bearer401() throws Exception {
            mvc.perform(post("/v1/auth/logout")
                            .header("Authorization", "Bearer !!!invalid-base64!!!"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        void missingBearerOnProtectedEndpoint401() throws Exception {
            mvc.perform(post("/v1/auth/logout"))
                    .andExpect(status().isUnauthorized());
        }
    }

    @Nested
    class DomainSeparation {

        @Test
        void authPrefixMatchesFixture() throws Exception {
            Path fixturesDir = resolveFixturesDir();
            Path prefixFile = fixturesDir.resolve("auth/prefix.txt");
            byte[] fixtureBytes = Files.readAllBytes(prefixFile);
            assertThat(AuthController.AUTH_PREFIX).isEqualTo(fixtureBytes);
        }

        private Path resolveFixturesDir() {
            Path dir = Path.of(System.getProperty("user.dir"));
            while (dir != null) {
                Path candidate = dir.resolve("spec/fixtures");
                if (Files.isDirectory(candidate)) {
                    return candidate;
                }
                dir = dir.getParent();
            }
            throw new IllegalStateException("spec/fixtures not found");
        }
    }
}
