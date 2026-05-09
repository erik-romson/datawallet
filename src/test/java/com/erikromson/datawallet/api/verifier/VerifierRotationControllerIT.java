package com.erikromson.datawallet.api.verifier;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.erikromson.datawallet.api.auth.AuthController;
import com.erikromson.datawallet.crypto.Ed25519;
import com.erikromson.datawallet.crypto.Random;
import com.erikromson.datawallet.domain.DirectoryRecordEntity;
import com.erikromson.datawallet.domain.DirectoryRecordRepository;
import com.erikromson.datawallet.domain.VerifierRepository;
import com.erikromson.datawallet.persistence.PostgresTestcontainer;
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

import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(PostgresTestcontainer.class)
class VerifierRotationControllerIT {

    @Autowired private MockMvc mvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private VerifierRepository verifierRepository;
    @Autowired private DirectoryRecordRepository directoryRecordRepository;

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();

    private static final String VALID_KDF_PARAMS =
            """
            {"alg":"argon2id","m":268435456,"t":3,"p":1,"version":19}
            """.strip();

    private static final String BELOW_FLOOR_KDF_PARAMS =
            """
            {"alg":"argon2id","m":1048576,"t":3,"p":1,"version":19}
            """.strip();

    // --- helpers ---

    private record RegisteredVerifier(UUID verifierId, Ed25519.KeyPair authKeyPair,
                                       byte[] encKeyId, byte[] authKeyId) {}

    private RegisteredVerifier registerVerifier() throws Exception {
        Ed25519.KeyPair kp = Ed25519.seedKeypair(Random.bytes(32));
        byte[] encKeyId = Random.bytes(16);
        byte[] authKeyId = Random.bytes(16);
        String handle = "rot" + System.nanoTime();

        String json = """
                {
                  "handle": "%s",
                  "enc_public_key": "%s",
                  "enc_key_id": "%s",
                  "auth_public_key": "%s",
                  "auth_key_id": "%s",
                  "wrapped_enc_private_key_blob": "%s",
                  "wrapped_auth_private_key_blob": "%s",
                  "kdf_salt": "%s",
                  "kdf_params": %s,
                  "client_password_score": 3
                }
                """.formatted(
                handle,
                B64URL.encodeToString(new byte[32]),
                B64URL.encodeToString(encKeyId),
                B64URL.encodeToString(kp.publicKey()),
                B64URL.encodeToString(authKeyId),
                B64URL.encodeToString(new byte[48]),
                B64URL.encodeToString(new byte[48]),
                B64URL.encodeToString(new byte[16]),
                VALID_KDF_PARAMS);

        MvcResult reg = mvc.perform(post("/v1/verifiers")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isCreated())
                .andReturn();

        UUID verifierId = UUID.fromString(
                objectMapper.readTree(reg.getResponse().getContentAsString())
                        .get("verifier_id").asText());

        return new RegisteredVerifier(verifierId, kp, encKeyId, authKeyId);
    }

    private String authenticate(UUID verifierId, Ed25519.KeyPair kp) throws Exception {
        MvcResult challengeResult = mvc.perform(post("/v1/auth/challenge")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"verifier_id\":\"" + verifierId + "\"}"))
                .andExpect(status().isOk())
                .andReturn();

        String nonce = objectMapper.readTree(challengeResult.getResponse().getContentAsString())
                .get("nonce").asText();

        byte[] nonceBytes = B64URL_DEC.decode(nonce);
        byte[] sig = Ed25519.signDetached(kp.privateKey(), AuthController.buildSignedBytes(nonceBytes));

        MvcResult verifyResult = mvc.perform(post("/v1/auth/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"verifier_id\":\"%s\",\"nonce\":\"%s\",\"signature\":\"%s\"}"
                                .formatted(verifierId, nonce, B64URL.encodeToString(sig))))
                .andExpect(status().isOk())
                .andReturn();

        return objectMapper.readTree(verifyResult.getResponse().getContentAsString())
                .get("session_token").asText();
    }

    private String passwordChangeBody(String kdfParams) {
        return """
                {
                  "wrapped_enc_private_key_blob": "%s",
                  "wrapped_auth_private_key_blob": "%s",
                  "kdf_salt": "%s",
                  "kdf_params": %s
                }
                """.formatted(
                B64URL.encodeToString(new byte[48]),
                B64URL.encodeToString(new byte[48]),
                B64URL.encodeToString(new byte[16]),
                kdfParams);
    }

    private String keyRotationBody(Ed25519.KeyPair newAuthKp,
                                    byte[] newEncKeyId, byte[] newAuthKeyId,
                                    byte[] oldEncKeyId, byte[] oldAuthKeyId,
                                    String kdfParams) {
        return """
                {
                  "enc_public_key": "%s",
                  "enc_key_id": "%s",
                  "auth_public_key": "%s",
                  "auth_key_id": "%s",
                  "wrapped_enc_private_key_blob": "%s",
                  "wrapped_auth_private_key_blob": "%s",
                  "kdf_salt": "%s",
                  "kdf_params": %s,
                  "old_enc_key_id": "%s",
                  "old_auth_key_id": "%s"
                }
                """.formatted(
                B64URL.encodeToString(new byte[32]),
                B64URL.encodeToString(newEncKeyId),
                B64URL.encodeToString(newAuthKp.publicKey()),
                B64URL.encodeToString(newAuthKeyId),
                B64URL.encodeToString(new byte[48]),
                B64URL.encodeToString(new byte[48]),
                B64URL.encodeToString(new byte[16]),
                kdfParams,
                B64URL.encodeToString(oldEncKeyId),
                B64URL.encodeToString(oldAuthKeyId));
    }

    // --- tests ---

    @Nested
    class PasswordChange {

        @Test
        void happyPath_blobsUpdatedAndSessionPreserved() throws Exception {
            var v = registerVerifier();
            String token = authenticate(v.verifierId(), v.authKeyPair());

            mvc.perform(post("/v1/verifiers/{id}/password", v.verifierId())
                            .header("Authorization", "Bearer " + token)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(passwordChangeBody(VALID_KDF_PARAMS)))
                    .andExpect(status().isNoContent());

            // session remains valid after password change
            mvc.perform(post("/v1/auth/logout")
                            .header("Authorization", "Bearer " + token))
                    .andExpect(status().isNoContent());
        }

        @Test
        void encKeyIdUnchangedAfterPasswordChange() throws Exception {
            var v = registerVerifier();
            String token = authenticate(v.verifierId(), v.authKeyPair());

            mvc.perform(post("/v1/verifiers/{id}/password", v.verifierId())
                            .header("Authorization", "Bearer " + token)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(passwordChangeBody(VALID_KDF_PARAMS)))
                    .andExpect(status().isNoContent());

            var updated = verifierRepository.findById(v.verifierId()).orElseThrow();
            assertThat(updated.getEncKeyId()).isEqualTo(v.encKeyId());
            assertThat(updated.getAuthKeyId()).isEqualTo(v.authKeyId());
        }

        @Test
        void nonSelf_403() throws Exception {
            var v1 = registerVerifier();
            var v2 = registerVerifier();
            String token = authenticate(v1.verifierId(), v1.authKeyPair());

            mvc.perform(post("/v1/verifiers/{id}/password", v2.verifierId())
                            .header("Authorization", "Bearer " + token)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(passwordChangeBody(VALID_KDF_PARAMS)))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.error.code").value("rotation_forbidden"));
        }

        @Test
        void kdfBelowFloor_422() throws Exception {
            var v = registerVerifier();
            String token = authenticate(v.verifierId(), v.authKeyPair());

            mvc.perform(post("/v1/verifiers/{id}/password", v.verifierId())
                            .header("Authorization", "Bearer " + token)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(passwordChangeBody(BELOW_FLOOR_KDF_PARAMS)))
                    .andExpect(status().isUnprocessableEntity())
                    .andExpect(jsonPath("$.error.code").value("kdf_below_floor"));
        }

        @Test
        void unauthenticated_401() throws Exception {
            var v = registerVerifier();

            mvc.perform(post("/v1/verifiers/{id}/password", v.verifierId())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(passwordChangeBody(VALID_KDF_PARAMS)))
                    .andExpect(status().isUnauthorized());
        }
    }

    @Nested
    class KeyRotation {

        @Test
        void happyPath_oldSessionInvalidatedAndNewKeyLoginWorks() throws Exception {
            var v = registerVerifier();
            String oldToken = authenticate(v.verifierId(), v.authKeyPair());

            Ed25519.KeyPair newAuthKp = Ed25519.seedKeypair(Random.bytes(32));
            byte[] newEncKeyId = Random.bytes(16);
            byte[] newAuthKeyId = Random.bytes(16);

            mvc.perform(post("/v1/verifiers/{id}/rotate-keys", v.verifierId())
                            .header("Authorization", "Bearer " + oldToken)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(keyRotationBody(newAuthKp, newEncKeyId, newAuthKeyId,
                                    v.encKeyId(), v.authKeyId(), VALID_KDF_PARAMS)))
                    .andExpect(status().isNoContent());

            // old session is now invalid
            mvc.perform(post("/v1/auth/logout")
                            .header("Authorization", "Bearer " + oldToken))
                    .andExpect(status().isUnauthorized());

            // login with the new auth key succeeds
            String newToken = authenticate(v.verifierId(), newAuthKp);
            assertThat(newToken).isNotBlank();

            mvc.perform(post("/v1/auth/logout")
                            .header("Authorization", "Bearer " + newToken))
                    .andExpect(status().isNoContent());
        }

        @Test
        void happyPath_directoryRecordsFlaggedPendingRevocation() throws Exception {
            var v = registerVerifier();
            String token = authenticate(v.verifierId(), v.authKeyPair());

            // insert directory records for the current enc and auth key IDs
            var encRecord = new DirectoryRecordEntity(
                    "verifier", v.verifierId(), v.encKeyId(),
                    "active", Instant.now(), Instant.now().plusSeconds(86400),
                    Instant.now(), new byte[16], null, new byte[32]);
            var authRecord = new DirectoryRecordEntity(
                    "verifier", v.verifierId(), v.authKeyId(),
                    "active", Instant.now(), Instant.now().plusSeconds(86400),
                    Instant.now(), new byte[16], null, new byte[32]);
            directoryRecordRepository.save(encRecord);
            directoryRecordRepository.save(authRecord);

            Ed25519.KeyPair newAuthKp = Ed25519.seedKeypair(Random.bytes(32));
            byte[] newEncKeyId = Random.bytes(16);
            byte[] newAuthKeyId = Random.bytes(16);

            mvc.perform(post("/v1/verifiers/{id}/rotate-keys", v.verifierId())
                            .header("Authorization", "Bearer " + token)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(keyRotationBody(newAuthKp, newEncKeyId, newAuthKeyId,
                                    v.encKeyId(), v.authKeyId(), VALID_KDF_PARAMS)))
                    .andExpect(status().isNoContent());

            List<DirectoryRecordEntity> encRecords =
                    directoryRecordRepository.findBySubjectIdAndKeyId(v.verifierId(), v.encKeyId());
            assertThat(encRecords).hasSize(1);
            assertThat(encRecords.get(0).isPendingRevocation()).isTrue();

            List<DirectoryRecordEntity> authRecords =
                    directoryRecordRepository.findBySubjectIdAndKeyId(v.verifierId(), v.authKeyId());
            assertThat(authRecords).hasSize(1);
            assertThat(authRecords.get(0).isPendingRevocation()).isTrue();
        }

        @Test
        void staleOldEncKeyId_422() throws Exception {
            var v = registerVerifier();
            String token = authenticate(v.verifierId(), v.authKeyPair());

            byte[] wrongKeyId = Random.bytes(16);
            Ed25519.KeyPair newAuthKp = Ed25519.seedKeypair(Random.bytes(32));

            mvc.perform(post("/v1/verifiers/{id}/rotate-keys", v.verifierId())
                            .header("Authorization", "Bearer " + token)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(keyRotationBody(newAuthKp, Random.bytes(16), Random.bytes(16),
                                    wrongKeyId, v.authKeyId(), VALID_KDF_PARAMS)))
                    .andExpect(status().isUnprocessableEntity())
                    .andExpect(jsonPath("$.error.code").value("key_rotation_stale"));
        }

        @Test
        void staleOldAuthKeyId_422() throws Exception {
            var v = registerVerifier();
            String token = authenticate(v.verifierId(), v.authKeyPair());

            byte[] wrongKeyId = Random.bytes(16);
            Ed25519.KeyPair newAuthKp = Ed25519.seedKeypair(Random.bytes(32));

            mvc.perform(post("/v1/verifiers/{id}/rotate-keys", v.verifierId())
                            .header("Authorization", "Bearer " + token)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(keyRotationBody(newAuthKp, Random.bytes(16), Random.bytes(16),
                                    v.encKeyId(), wrongKeyId, VALID_KDF_PARAMS)))
                    .andExpect(status().isUnprocessableEntity())
                    .andExpect(jsonPath("$.error.code").value("key_rotation_stale"));
        }

        @Test
        void nonSelf_403() throws Exception {
            var v1 = registerVerifier();
            var v2 = registerVerifier();
            String token = authenticate(v1.verifierId(), v1.authKeyPair());

            Ed25519.KeyPair newAuthKp = Ed25519.seedKeypair(Random.bytes(32));

            mvc.perform(post("/v1/verifiers/{id}/rotate-keys", v2.verifierId())
                            .header("Authorization", "Bearer " + token)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(keyRotationBody(newAuthKp, Random.bytes(16), Random.bytes(16),
                                    v2.encKeyId(), v2.authKeyId(), VALID_KDF_PARAMS)))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.error.code").value("rotation_forbidden"));
        }

        @Test
        void kdfBelowFloor_422() throws Exception {
            var v = registerVerifier();
            String token = authenticate(v.verifierId(), v.authKeyPair());

            Ed25519.KeyPair newAuthKp = Ed25519.seedKeypair(Random.bytes(32));

            mvc.perform(post("/v1/verifiers/{id}/rotate-keys", v.verifierId())
                            .header("Authorization", "Bearer " + token)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(keyRotationBody(newAuthKp, Random.bytes(16), Random.bytes(16),
                                    v.encKeyId(), v.authKeyId(), BELOW_FLOOR_KDF_PARAMS)))
                    .andExpect(status().isUnprocessableEntity())
                    .andExpect(jsonPath("$.error.code").value("kdf_below_floor"));
        }

        @Test
        void unauthenticated_401() throws Exception {
            var v = registerVerifier();
            Ed25519.KeyPair newAuthKp = Ed25519.seedKeypair(Random.bytes(32));

            mvc.perform(post("/v1/verifiers/{id}/rotate-keys", v.verifierId())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(keyRotationBody(newAuthKp, Random.bytes(16), Random.bytes(16),
                                    v.encKeyId(), v.authKeyId(), VALID_KDF_PARAMS)))
                    .andExpect(status().isUnauthorized());
        }
    }
}
