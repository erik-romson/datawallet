package com.erikromson.datawallet.api.shared;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.erikromson.datawallet.crypto.Ed25519;
import com.erikromson.datawallet.crypto.Random;
import com.erikromson.datawallet.domain.EntryEntity;
import com.erikromson.datawallet.domain.EntryRecipientEntity;
import com.erikromson.datawallet.domain.EntryRecipientRepository;
import com.erikromson.datawallet.domain.EntryRepository;
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

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(PostgresTestcontainer.class)
class SharedControllerIT {

    @Autowired private MockMvc mvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private EntryRepository entryRepository;
    @Autowired private EntryRecipientRepository entryRecipientRepository;

    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64_DEC = Base64.getUrlDecoder();

    // --- helpers ---

    private record Verifier(UUID id, String bearer) {}

    private Verifier registerAndAuth() throws Exception {
        byte[] seed = Random.bytes(32);
        Ed25519.KeyPair kp = Ed25519.seedKeypair(seed);
        String handle = "sv" + System.nanoTime();

        String regJson = """
                {"handle":"%s","display_name":"T","enc_public_key":"%s","enc_key_id":"%s",
                "auth_public_key":"%s","auth_key_id":"%s",
                "wrapped_enc_private_key_blob":"%s","wrapped_auth_private_key_blob":"%s",
                "kdf_salt":"%s","kdf_params":{"alg":"argon2id","m":268435456,"t":3,"p":1,"version":19},
                "client_password_score":3}
                """.formatted(handle,
                B64.encodeToString(new byte[32]), B64.encodeToString(new byte[16]),
                B64.encodeToString(kp.publicKey()), B64.encodeToString(new byte[16]),
                B64.encodeToString(new byte[48]), B64.encodeToString(new byte[48]),
                B64.encodeToString(new byte[16]));

        MvcResult reg = mvc.perform(post("/v1/verifiers")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(regJson))
                .andExpect(status().isCreated())
                .andReturn();
        UUID verifierId = UUID.fromString(
                objectMapper.readTree(reg.getResponse().getContentAsString()).get("verifier_id").asText());

        MvcResult challengeResult = mvc.perform(post("/v1/auth/challenge")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"verifier_id\":\"" + verifierId + "\"}"))
                .andReturn();
        String nonceB64 = objectMapper.readTree(challengeResult.getResponse().getContentAsString())
                .get("nonce").asText();

        byte[] nonceBytes = B64_DEC.decode(nonceB64);
        byte[] prefix = "datawallet-auth-v1\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] signedBytes = new byte[prefix.length + nonceBytes.length];
        System.arraycopy(prefix, 0, signedBytes, 0, prefix.length);
        System.arraycopy(nonceBytes, 0, signedBytes, prefix.length, nonceBytes.length);
        byte[] sig = Ed25519.signDetached(kp.privateKey(), signedBytes);

        MvcResult verifyResult = mvc.perform(post("/v1/auth/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"verifier_id\":\"" + verifierId
                                + "\",\"nonce\":\"" + nonceB64
                                + "\",\"signature\":\"" + B64.encodeToString(sig) + "\"}"))
                .andReturn();
        String bearer = objectMapper.readTree(verifyResult.getResponse().getContentAsString())
                .get("session_token").asText();

        return new Verifier(verifierId, bearer);
    }

    private UUID seedEntry(UUID verifierId, Instant createdAt, byte[] signedEnvelope) {
        UUID entryId = UUID.randomUUID();
        UUID issuerId = UUID.randomUUID();
        byte[] fakeHash = new byte[32];
        byte[] fakeKeyId = new byte[16];
        entryRepository.save(new EntryEntity(
                entryId, 1, issuerId, true, createdAt, null,
                signedEnvelope, fakeHash, "Test Issuer", fakeKeyId, "test description"));
        entryRecipientRepository.save(new EntryRecipientEntity(entryId, 1, verifierId, fakeKeyId));
        return entryId;
    }

    private static byte[] fakeEnvelope() {
        byte[] b = new byte[32];
        Random.bytes(32);
        java.util.Arrays.fill(b, (byte) 0xAB);
        return b;
    }

    private static Path resolveFixturesDir() {
        Path dir = Path.of(System.getProperty("user.dir"));
        while (dir != null) {
            Path candidate = dir.resolve("spec/fixtures");
            if (java.nio.file.Files.isDirectory(candidate)) return candidate;
            dir = dir.getParent();
        }
        throw new IllegalStateException("spec/fixtures not found");
    }

    // --- tests ---

    @Test
    void listHappyPathReturnsBothOrderedDesc() throws Exception {
        Verifier v = registerAndAuth();
        Instant older = Instant.now().minusSeconds(10);
        Instant newer = Instant.now().minusSeconds(1);
        UUID idOlder = seedEntry(v.id(), older, fakeEnvelope());
        UUID idNewer = seedEntry(v.id(), newer, fakeEnvelope());

        MvcResult result = mvc.perform(get("/v1/shared")
                        .header("Authorization", "Bearer " + v.bearer()))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        JsonNode items = body.get("items");
        assertThat(items.size()).isEqualTo(2);
        assertThat(items.get(0).get("entry_id").asText()).isEqualTo(idNewer.toString());
        assertThat(items.get(1).get("entry_id").asText()).isEqualTo(idOlder.toString());
        assertThat(body.has("next_cursor")).isFalse();
    }

    @Test
    void limitOneCursorReturnsSecondItem() throws Exception {
        Verifier v = registerAndAuth();
        Instant older = Instant.now().minusSeconds(10);
        Instant newer = Instant.now().minusSeconds(1);
        UUID idOlder = seedEntry(v.id(), older, fakeEnvelope());
        UUID idNewer = seedEntry(v.id(), newer, fakeEnvelope());

        MvcResult page1 = mvc.perform(get("/v1/shared?limit=1")
                        .header("Authorization", "Bearer " + v.bearer()))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode body1 = objectMapper.readTree(page1.getResponse().getContentAsString());
        assertThat(body1.get("items").size()).isEqualTo(1);
        assertThat(body1.get("items").get(0).get("entry_id").asText()).isEqualTo(idNewer.toString());
        String nextCursor = body1.get("next_cursor").asText();
        assertThat(nextCursor).isNotBlank();

        MvcResult page2 = mvc.perform(get("/v1/shared?cursor=" + nextCursor)
                        .header("Authorization", "Bearer " + v.bearer()))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode body2 = objectMapper.readTree(page2.getResponse().getContentAsString());
        assertThat(body2.get("items").size()).isEqualTo(1);
        assertThat(body2.get("items").get(0).get("entry_id").asText()).isEqualTo(idOlder.toString());
        assertThat(body2.has("next_cursor")).isFalse();
    }

    @Test
    void sinceFilterExcludesOlderEntries() throws Exception {
        Verifier v = registerAndAuth();
        Instant older = Instant.now().minusSeconds(10);
        Instant newer = Instant.now().minusSeconds(1);
        seedEntry(v.id(), older, fakeEnvelope());
        UUID idNewer = seedEntry(v.id(), newer, fakeEnvelope());

        String since = Instant.now().minusSeconds(5).toString();
        MvcResult result = mvc.perform(get("/v1/shared?since=" + since)
                        .header("Authorization", "Bearer " + v.bearer()))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode items = objectMapper.readTree(result.getResponse().getContentAsString()).get("items");
        assertThat(items.size()).isEqualTo(1);
        assertThat(items.get(0).get("entry_id").asText()).isEqualTo(idNewer.toString());
    }

    @Test
    void sinceAndCursorBothPresent400() throws Exception {
        Verifier v = registerAndAuth();
        mvc.perform(get("/v1/shared?since=2026-01-01T00:00:00Z&cursor=abc")
                        .header("Authorization", "Bearer " + v.bearer()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("schema_violation"));
    }

    @Test
    void detailReturnsExactFixtureBytes() throws Exception {
        Verifier v = registerAndAuth();
        byte[] cborBytes = Files.readAllBytes(
                resolveFixturesDir().resolve("envelopes/basic-1-recipient.cbor"));
        UUID entryId = seedEntry(v.id(), Instant.now(), cborBytes);

        byte[] responseBody = mvc.perform(get("/v1/shared/" + entryId)
                        .header("Authorization", "Bearer " + v.bearer()))
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/cbor"))
                .andReturn()
                .getResponse()
                .getContentAsByteArray();

        assertThat(responseBody).isEqualTo(cborBytes);
    }

    @Test
    void nonRecipientVerifier404() throws Exception {
        Verifier owner = registerAndAuth();
        Verifier other = registerAndAuth();
        UUID entryId = seedEntry(owner.id(), Instant.now(), fakeEnvelope());

        mvc.perform(get("/v1/shared/" + entryId)
                        .header("Authorization", "Bearer " + other.bearer()))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("entry_not_found"));
    }

    @Test
    void pastRecipientReturns410() throws Exception {
        Verifier v = registerAndAuth();
        UUID entryId = UUID.randomUUID();
        UUID issuerId = UUID.randomUUID();
        byte[] fakeHash = new byte[32];
        byte[] fakeKeyId = new byte[16];

        // version 1: v is recipient, not current
        entryRepository.save(new EntryEntity(
                entryId, 1, issuerId, false, Instant.now().minusSeconds(5), Instant.now().minusSeconds(1),
                fakeEnvelope(), fakeHash, "Issuer", fakeKeyId, "old"));
        entryRecipientRepository.save(new EntryRecipientEntity(entryId, 1, v.id(), fakeKeyId));

        // version 2: current, v is NOT recipient
        UUID otherId = UUID.randomUUID();
        entryRepository.save(new EntryEntity(
                entryId, 2, issuerId, true, Instant.now(), null,
                fakeEnvelope(), fakeHash, "Issuer", fakeKeyId, "new"));
        entryRecipientRepository.save(new EntryRecipientEntity(entryId, 2, otherId, fakeKeyId));

        mvc.perform(get("/v1/shared/" + entryId)
                        .header("Authorization", "Bearer " + v.bearer()))
                .andExpect(status().isGone())
                .andExpect(jsonPath("$.error.code").value("entry_purged"));
    }
}
