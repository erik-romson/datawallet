package com.erikromson.datawallet.api.verifier;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.erikromson.datawallet.crypto.Fingerprint;
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

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(PostgresTestcontainer.class)
class VerifierDiscoveryIT {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper objectMapper;

    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    private static String uniqueHandle() {
        return "disc" + System.nanoTime();
    }

    private static byte[] knownEncKey() {
        byte[] b = new byte[32];
        Arrays.fill(b, (byte) 0x42);
        return b;
    }

    private String registerDiscoverable(String handle, byte[] encPublicKey) throws Exception {
        String json = """
                {
                  "handle": "%s",
                  "display_name": "Display %s",
                  "discoverable": true,
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
                """.formatted(
                handle, handle,
                B64.encodeToString(encPublicKey),
                B64.encodeToString(new byte[16]),
                B64.encodeToString(new byte[32]),
                B64.encodeToString(new byte[16]),
                B64.encodeToString(new byte[48]),
                B64.encodeToString(new byte[48]),
                B64.encodeToString(new byte[16])
        );
        MvcResult result = mvc.perform(post("/v1/verifiers")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isCreated())
                .andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString())
                .get("verifier_id").asText();
    }

    private void registerNotDiscoverable(String handle) throws Exception {
        String json = """
                {
                  "handle": "%s",
                  "display_name": "Hidden %s",
                  "enc_public_key": "%s",
                  "enc_key_id": "%s",
                  "auth_public_key": "%s",
                  "auth_key_id": "%s",
                  "wrapped_enc_private_key_blob": "%s",
                  "wrapped_auth_private_key_blob": "%s",
                  "kdf_salt": "%s",
                  "kdf_params": {"alg":"argon2id","m":268435456,"t":3,"p":1,"version":19}
                }
                """.formatted(
                handle, handle,
                B64.encodeToString(new byte[32]),
                B64.encodeToString(new byte[16]),
                B64.encodeToString(new byte[32]),
                B64.encodeToString(new byte[16]),
                B64.encodeToString(new byte[48]),
                B64.encodeToString(new byte[48]),
                B64.encodeToString(new byte[16])
        );
        mvc.perform(post("/v1/verifiers")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isCreated());
    }

    private JsonNode listSince(Instant since) throws Exception {
        MvcResult result = mvc.perform(get("/v1/verifiers?since=" + since.toString()))
                .andExpect(status().isOk())
                .andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }

    private JsonNode listWithCursor(String cursor) throws Exception {
        MvcResult result = mvc.perform(get("/v1/verifiers?cursor=" + cursor + "&limit=1"))
                .andExpect(status().isOk())
                .andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }

    // --- tests ---

    @Test
    void onlyDiscoverableActiveReturned() throws Exception {
        Instant before = Instant.now();
        String discId = registerDiscoverable(uniqueHandle(), new byte[32]);
        registerNotDiscoverable(uniqueHandle());

        JsonNode body = listSince(before);
        JsonNode items = body.get("items");
        assertThat(items.size()).isEqualTo(1);
        assertThat(items.get(0).get("verifier_id").asText()).isEqualTo(discId);
    }

    @Test
    void paginationRoundTrip() throws Exception {
        Instant before = Instant.now();
        String id1 = registerDiscoverable(uniqueHandle(), new byte[32]);
        String id2 = registerDiscoverable(uniqueHandle(), new byte[32]);

        // First page: since=before, limit=1 → should return id2 (newest) + cursor
        MvcResult page1Result = mvc.perform(
                        get("/v1/verifiers?since=" + before + "&limit=1"))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode page1 = objectMapper.readTree(page1Result.getResponse().getContentAsString());
        assertThat(page1.get("items").size()).isEqualTo(1);
        assertThat(page1.get("items").get(0).get("verifier_id").asText()).isEqualTo(id2);
        String nextCursor = page1.get("next_cursor").asText();
        assertThat(nextCursor).isNotBlank();

        // Second page via cursor → id1 is the next-oldest item after id2
        JsonNode page2 = listWithCursor(nextCursor);
        assertThat(page2.get("items").size()).isEqualTo(1);
        assertThat(page2.get("items").get(0).get("verifier_id").asText()).isEqualTo(id1);
    }

    @Test
    void fullWalkProducesNoOverlap() throws Exception {
        String id1 = registerDiscoverable(uniqueHandle(), new byte[32]);
        String id2 = registerDiscoverable(uniqueHandle(), new byte[32]);
        String id3 = registerDiscoverable(uniqueHandle(), new byte[32]);
        Set<String> registered = Set.of(id1, id2, id3);

        // Walk ALL pages with limit=1, collecting every returned verifier_id
        Set<String> seen = new HashSet<>();
        String cursor = null;
        int maxPages = 200;
        while (maxPages-- > 0) {
            String url = cursor == null
                    ? "/v1/verifiers?limit=1"
                    : "/v1/verifiers?limit=1&cursor=" + cursor;
            MvcResult r = mvc.perform(get(url)).andExpect(status().isOk()).andReturn();
            JsonNode body = objectMapper.readTree(r.getResponse().getContentAsString());
            JsonNode items = body.get("items");
            for (JsonNode item : items) {
                String id = item.get("verifier_id").asText();
                assertThat(seen).as("duplicate item: " + id).doesNotContain(id);
                seen.add(id);
            }
            JsonNode nc = body.get("next_cursor");
            cursor = (nc != null && !nc.isNull()) ? nc.asText() : null;
            if (cursor == null) break;
        }

        assertThat(seen).containsAll(registered);
    }

    @Test
    void sinceFilterExcludesOlderVerifier() throws Exception {
        String idBefore = registerDiscoverable(uniqueHandle(), new byte[32]);
        Instant cutoff = Instant.now(); // After idBefore's created_at
        String idAfter = registerDiscoverable(uniqueHandle(), new byte[32]);

        JsonNode body = listSince(cutoff);
        List<String> ids = new ArrayList<>();
        for (JsonNode item : body.get("items")) {
            ids.add(item.get("verifier_id").asText());
        }

        assertThat(ids).contains(idAfter);
        assertThat(ids).doesNotContain(idBefore);
    }

    @Test
    void sinceAndCursorBothPresent400() throws Exception {
        mvc.perform(get("/v1/verifiers?since=2026-01-01T00:00:00Z&cursor=abc"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("schema_violation"))
                .andExpect(jsonPath("$.trace_id").exists());
    }

    @Test
    void badCursorReturns400() throws Exception {
        mvc.perform(get("/v1/verifiers?cursor=not-a-valid-cursor!!!!"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("bad_cursor"))
                .andExpect(jsonPath("$.trace_id").exists());
    }

    @Test
    void keyFingerprintMatchesRendering() throws Exception {
        byte[] encKey = knownEncKey();
        Instant before = Instant.now();
        registerDiscoverable(uniqueHandle(), encKey);

        String expectedFingerprint = Fingerprint.render(encKey);

        JsonNode body = listSince(before);
        JsonNode items = body.get("items");
        assertThat(items.size()).isEqualTo(1);
        assertThat(items.get(0).get("key_fingerprint").asText()).isEqualTo(expectedFingerprint);
    }

    @Test
    void discoverableTrueRequiresDisplayName400() throws Exception {
        String json = """
                {
                  "handle": "%s",
                  "discoverable": true,
                  "enc_public_key": "%s",
                  "enc_key_id": "%s",
                  "auth_public_key": "%s",
                  "auth_key_id": "%s",
                  "wrapped_enc_private_key_blob": "%s",
                  "wrapped_auth_private_key_blob": "%s",
                  "kdf_salt": "%s",
                  "kdf_params": {"alg":"argon2id","m":268435456,"t":3,"p":1,"version":19}
                }
                """.formatted(
                uniqueHandle(),
                B64.encodeToString(new byte[32]),
                B64.encodeToString(new byte[16]),
                B64.encodeToString(new byte[32]),
                B64.encodeToString(new byte[16]),
                B64.encodeToString(new byte[48]),
                B64.encodeToString(new byte[48]),
                B64.encodeToString(new byte[16])
        );

        mvc.perform(post("/v1/verifiers")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("schema_violation"))
                .andExpect(jsonPath("$.trace_id").exists());
    }

    @Test
    void listResponseHasCacheControlHeader() throws Exception {
        mvc.perform(get("/v1/verifiers"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "public, max-age=300"));
    }
}
