package com.erikromson.datawallet.api.verifier;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.erikromson.datawallet.persistence.PostgresTestcontainer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

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
class VerifierControllerIT {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper objectMapper;

    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    private static String b64(int len) {
        byte[] b = new byte[len];
        java.util.Arrays.fill(b, (byte) 0x42);
        return B64.encodeToString(b);
    }

    private static String registrationJson(String handle) {
        return registrationJson(handle, 268_435_456L);
    }

    private static String registrationJson(String handle, long m) {
        return """
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
                  "kdf_params": {"alg":"argon2id","m":%d,"t":3,"p":1,"version":19},
                  "client_password_score": 3
                }
                """.formatted(handle, b64(32), b64(16), b64(32), b64(16),
                b64(48), b64(48), b64(16), m);
    }

    @Test
    void happyPathRegisterAndLoginBlob() throws Exception {
        String handle = "alice" + System.nanoTime();

        MvcResult regResult = mvc.perform(post("/v1/verifiers")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationJson(handle)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.verifier_id").exists())
                .andReturn();

        JsonNode regBody = objectMapper.readTree(regResult.getResponse().getContentAsString());
        String verifierId = regBody.get("verifier_id").asText();
        UUID uuid = UUID.fromString(verifierId);
        int versionNibble = (int) ((uuid.getMostSignificantBits() >> 12) & 0xF);
        assertThat(versionNibble).isEqualTo(7);

        MvcResult blobResult = mvc.perform(get("/v1/verifiers/{handle}/login-blob", handle))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verifier_id").value(verifierId))
                .andExpect(jsonPath("$.auth_public_key").value(b64(32)))
                .andExpect(jsonPath("$.auth_key_id").value(b64(16)))
                .andExpect(jsonPath("$.wrapped_enc_private_key_blob").value(b64(48)))
                .andExpect(jsonPath("$.wrapped_auth_private_key_blob").value(b64(48)))
                .andExpect(jsonPath("$.kdf_salt").value(b64(16)))
                .andExpect(jsonPath("$.kdf_params.alg").value("argon2id"))
                .andExpect(jsonPath("$.kdf_params.m").value(268_435_456))
                .andExpect(jsonPath("$.kdf_params.t").value(3))
                .andExpect(jsonPath("$.kdf_params.p").value(1))
                .andExpect(jsonPath("$.kdf_params.version").value(19))
                .andReturn();
    }

    @Test
    void invalidHandle400() throws Exception {
        mvc.perform(post("/v1/verifiers")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationJson("UPPERCASE")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("handle_invalid"))
                .andExpect(jsonPath("$.trace_id").exists());
    }

    @Test
    void reservedHandle409() throws Exception {
        mvc.perform(post("/v1/verifiers")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationJson("admin")))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error.code").value("handle_reserved"))
                .andExpect(jsonPath("$.trace_id").exists());
    }

    @Test
    void duplicateHandle409() throws Exception {
        String handle = "dup" + System.nanoTime();

        mvc.perform(post("/v1/verifiers")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationJson(handle)))
                .andExpect(status().isCreated());

        mvc.perform(post("/v1/verifiers")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationJson(handle)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error.code").value("handle_taken"))
                .andExpect(jsonPath("$.trace_id").exists());
    }

    @Test
    void nativeFloorTooLow422() throws Exception {
        String handle = "native" + System.nanoTime();

        mvc.perform(post("/v1/verifiers")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationJson(handle, 67_108_864L)))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error.code").value("kdf_below_floor"))
                .andExpect(jsonPath("$.trace_id").exists());
    }

    @Test
    void webFloorAccepted() throws Exception {
        String handle = "webuser" + System.nanoTime();

        mvc.perform(post("/v1/verifiers")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Origin", "https://web.example.com")
                        .content(registrationJson(handle, 67_108_864L)))
                .andExpect(status().isCreated());
    }

    @Test
    void missingRequiredField400() throws Exception {
        String json = """
                {
                  "display_name": "Test",
                  "enc_public_key": "%s",
                  "enc_key_id": "%s",
                  "auth_public_key": "%s",
                  "auth_key_id": "%s",
                  "wrapped_enc_private_key_blob": "%s",
                  "wrapped_auth_private_key_blob": "%s",
                  "kdf_salt": "%s",
                  "kdf_params": {"alg":"argon2id","m":268435456,"t":3,"p":1,"version":19}
                }
                """.formatted(b64(32), b64(16), b64(32), b64(16), b64(48), b64(48), b64(16));

        mvc.perform(post("/v1/verifiers")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("validation_error"))
                .andExpect(jsonPath("$.error.message").exists())
                .andExpect(jsonPath("$.trace_id").exists());
    }

    @Test
    void errorEnvelopeShape() throws Exception {
        MvcResult result = mvc.perform(post("/v1/verifiers")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationJson("INVALID!")))
                .andExpect(status().isBadRequest())
                .andReturn();

        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertThat(body.has("error")).isTrue();
        assertThat(body.get("error").has("code")).isTrue();
        assertThat(body.get("error").has("message")).isTrue();
        assertThat(body.has("trace_id")).isTrue();
        assertThat(body.get("trace_id").asText()).isNotBlank();
    }

    @Test
    void loginBlobNotFound404() throws Exception {
        mvc.perform(get("/v1/verifiers/nonexistent/login-blob"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("handle_not_found"));
    }
}
