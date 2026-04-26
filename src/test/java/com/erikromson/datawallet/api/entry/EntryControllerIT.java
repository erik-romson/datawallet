package com.erikromson.datawallet.api.entry;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.erikromson.datawallet.domain.EntryEntity;
import com.erikromson.datawallet.domain.EntryRecipientEntity;
import com.erikromson.datawallet.domain.EntryRecipientRepository;
import com.erikromson.datawallet.domain.EntryRepository;
import com.erikromson.datawallet.persistence.PostgresTestcontainer;
import com.erikromson.datawallet.security.HeaderIssuerPrincipalResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"test", "it"})
@Import({PostgresTestcontainer.class, FixtureIssuerKeyResolver.class})
class EntryControllerIT {

    private static final String ACME_ISSUER_ID = "01941f297c-0070-5090-5050-505050505050";
    // UUID canonical form: 01941f29-7c00-7050-9050-505050505050
    private static final String ACME_ISSUER_UUID = toUuidString("01941f297c0070509050505050505050");
    private static final String BASIC_ENTRY_ID = toUuidString("0194244fd80072428242424242424242");
    private static final String UPDATE_ENTRY_ID = toUuidString("01942976340073438343434343434343");

    @Autowired private MockMvc mvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private EntryRepository entryRepository;
    @Autowired private EntryRecipientRepository entryRecipientRepository;
    @Autowired private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void cleanupTestEntries() {
        jdbcTemplate.update("DELETE FROM entry_recipients WHERE entry_id IN (?::uuid, ?::uuid)",
                BASIC_ENTRY_ID, UPDATE_ENTRY_ID);
        jdbcTemplate.update("DELETE FROM entries WHERE entry_id IN (?::uuid, ?::uuid)",
                BASIC_ENTRY_ID, UPDATE_ENTRY_ID);
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

    private static String toUuidString(String hex) {
        // Convert 32-char hex to UUID canonical form: 8-4-4-4-12
        return hex.substring(0, 8) + "-" + hex.substring(8, 12) + "-"
                + hex.substring(12, 16) + "-" + hex.substring(16, 20) + "-"
                + hex.substring(20);
    }

    @Test
    void happyPathPostAndRetrieve() throws Exception {
        byte[] cborBytes = Files.readAllBytes(
                resolveFixturesDir().resolve("envelopes/basic-1-recipient.cbor"));

        MvcResult result = mvc.perform(post("/v1/entries")
                        .header(HeaderIssuerPrincipalResolver.HEADER, ACME_ISSUER_UUID)
                        .contentType("application/cbor")
                        .content(cborBytes))
                .andExpect(status().isCreated())
                .andReturn();

        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertThat(body.get("entry_id").asText()).isEqualTo(BASIC_ENTRY_ID);
        assertThat(body.get("version").asInt()).isEqualTo(1);

        // Verify the raw bytes are stored exactly
        EntryEntity stored = entryRepository.findCurrentByEntryId(UUID.fromString(BASIC_ENTRY_ID))
                .orElseThrow();
        assertThat(stored.getSignedEnvelope()).isEqualTo(cborBytes);
    }

    @Test
    void issuerMismatchHeaderReturns403() throws Exception {
        byte[] cborBytes = Files.readAllBytes(
                resolveFixturesDir().resolve("envelopes/basic-1-recipient.cbor"));
        UUID wrongIssuer = UUID.randomUUID();

        mvc.perform(post("/v1/entries")
                        .header(HeaderIssuerPrincipalResolver.HEADER, wrongIssuer.toString())
                        .contentType("application/cbor")
                        .content(cborBytes))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error.code").value("issuer_mismatch"));
    }

    @Test
    void badSignatureReturns422() throws Exception {
        byte[] cborBytes = Files.readAllBytes(
                resolveFixturesDir().resolve("envelopes/invalid/wrong-issuer-key.cbor"));

        mvc.perform(post("/v1/entries")
                        .header(HeaderIssuerPrincipalResolver.HEADER, ACME_ISSUER_UUID)
                        .contentType("application/cbor")
                        .content(cborBytes))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error.code").value("signature_invalid"));
    }

    @Test
    void duplicateEntryIdReturns409() throws Exception {
        byte[] cborBytes = Files.readAllBytes(
                resolveFixturesDir().resolve("envelopes/basic-1-recipient.cbor"));

        mvc.perform(post("/v1/entries")
                        .header(HeaderIssuerPrincipalResolver.HEADER, ACME_ISSUER_UUID)
                        .contentType("application/cbor")
                        .content(cborBytes))
                .andExpect(status().isCreated());

        mvc.perform(post("/v1/entries")
                        .header(HeaderIssuerPrincipalResolver.HEADER, ACME_ISSUER_UUID)
                        .contentType("application/cbor")
                        .content(cborBytes))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error.code").value("entry_id_taken"));
    }

    @Test
    void putUpdatesVersionAndReturnsV2Bytes() throws Exception {
        // Seed a v1 entry for the update fixture's entry_id with a different ciphertext_hash
        UUID updateEntryId = UUID.fromString(UPDATE_ENTRY_ID);
        UUID issuerId = UUID.fromString(ACME_ISSUER_UUID);
        byte[] differentHash = new byte[32];
        java.util.Arrays.fill(differentHash, (byte) 0x11);

        entryRepository.save(new EntryEntity(
                updateEntryId, 1, issuerId, true, Instant.now().minusSeconds(60), null,
                new byte[]{0x01}, differentHash, "Acme Corp",
                java.util.HexFormat.of().parseHex("f849d67325facf04177bc663b2dc5440"), "seed"));

        byte[] updateBytes = Files.readAllBytes(
                resolveFixturesDir().resolve("envelopes/allow-list-update-v2.cbor"));

        MvcResult result = mvc.perform(put("/v1/entries/" + UPDATE_ENTRY_ID)
                        .header(HeaderIssuerPrincipalResolver.HEADER, ACME_ISSUER_UUID)
                        .contentType("application/cbor")
                        .content(updateBytes))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertThat(body.get("entry_id").asText()).isEqualTo(UPDATE_ENTRY_ID);
        assertThat(body.get("version").asInt()).isEqualTo(2);

        // Retrieval returns v2 bytes
        EntryEntity current = entryRepository.findCurrentByEntryId(updateEntryId).orElseThrow();
        assertThat(current.getSignedEnvelope()).isEqualTo(updateBytes);
        assertThat(current.getVersion()).isEqualTo(2);
    }

    @Test
    void putNonExistentEntryReturns404() throws Exception {
        byte[] updateBytes = Files.readAllBytes(
                resolveFixturesDir().resolve("envelopes/allow-list-update-v2.cbor"));

        mvc.perform(put("/v1/entries/" + UPDATE_ENTRY_ID)
                        .header(HeaderIssuerPrincipalResolver.HEADER, ACME_ISSUER_UUID)
                        .contentType("application/cbor")
                        .content(updateBytes))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("entry_not_found"));
    }

    @Test
    void putSameCiphertextHashReturns409RewrapForbidden() throws Exception {
        byte[] updateBytes = Files.readAllBytes(
                resolveFixturesDir().resolve("envelopes/allow-list-update-v2.cbor"));

        // Decode the ciphertext_hash from the fixture to seed with the same hash
        com.erikromson.datawallet.envelope.EnvelopeCodec codec =
                new com.erikromson.datawallet.envelope.EnvelopeCodec();
        com.erikromson.datawallet.envelope.SharedEnvelope env = codec.decode(updateBytes);

        UUID updateEntryId = UUID.fromString(UPDATE_ENTRY_ID);
        UUID issuerId = UUID.fromString(ACME_ISSUER_UUID);

        // Seed with SAME ciphertext_hash as the fixture
        entryRepository.save(new EntryEntity(
                updateEntryId, 1, issuerId, true, Instant.now().minusSeconds(60), null,
                new byte[]{0x01}, env.ciphertextHash(), "Acme Corp",
                java.util.HexFormat.of().parseHex("f849d67325facf04177bc663b2dc5440"), "seed"));

        mvc.perform(put("/v1/entries/" + UPDATE_ENTRY_ID)
                        .header(HeaderIssuerPrincipalResolver.HEADER, ACME_ISSUER_UUID)
                        .contentType("application/cbor")
                        .content(updateBytes))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error.code").value("rewrap_only_forbidden"));
    }

    @Test
    void concurrentPutsProduceOneWinnerAndOneVersionConflict() throws Exception {
        byte[] updateBytes = Files.readAllBytes(
                resolveFixturesDir().resolve("envelopes/allow-list-update-v2.cbor"));

        com.erikromson.datawallet.envelope.EnvelopeCodec codec =
                new com.erikromson.datawallet.envelope.EnvelopeCodec();
        com.erikromson.datawallet.envelope.SharedEnvelope env = codec.decode(updateBytes);

        UUID updateEntryId = UUID.fromString(UPDATE_ENTRY_ID);
        UUID issuerId = UUID.fromString(ACME_ISSUER_UUID);
        byte[] differentHash = new byte[32];
        java.util.Arrays.fill(differentHash, (byte) 0x22);

        entryRepository.save(new EntryEntity(
                updateEntryId, 1, issuerId, true, Instant.now().minusSeconds(60), null,
                new byte[]{0x01}, differentHash, "Acme Corp",
                java.util.HexFormat.of().parseHex("f849d67325facf04177bc663b2dc5440"), "seed"));

        CountDownLatch start = new CountDownLatch(1);
        ExecutorService exec = Executors.newFixedThreadPool(2);

        Future<Integer> t1 = exec.submit(() -> {
            start.await();
            return mvc.perform(put("/v1/entries/" + UPDATE_ENTRY_ID)
                            .header(HeaderIssuerPrincipalResolver.HEADER, ACME_ISSUER_UUID)
                            .contentType("application/cbor")
                            .content(updateBytes))
                    .andReturn().getResponse().getStatus();
        });

        Future<Integer> t2 = exec.submit(() -> {
            start.await();
            return mvc.perform(put("/v1/entries/" + UPDATE_ENTRY_ID)
                            .header(HeaderIssuerPrincipalResolver.HEADER, ACME_ISSUER_UUID)
                            .contentType("application/cbor")
                            .content(updateBytes))
                    .andReturn().getResponse().getStatus();
        });

        start.countDown();
        int status1 = t1.get();
        int status2 = t2.get();
        exec.shutdown();

        // Exactly one winner (200), one loser (409 version_conflict or rewrap_only_forbidden)
        int successes = (status1 == 200 ? 1 : 0) + (status2 == 200 ? 1 : 0);
        int conflicts = (status1 == 409 ? 1 : 0) + (status2 == 409 ? 1 : 0);
        assertThat(successes).as("exactly one PUT should succeed").isEqualTo(1);
        assertThat(conflicts).as("exactly one PUT should conflict").isEqualTo(1);
    }

    @Test
    void missingIssuerHeaderReturns401() throws Exception {
        byte[] cborBytes = Files.readAllBytes(
                resolveFixturesDir().resolve("envelopes/basic-1-recipient.cbor"));

        mvc.perform(post("/v1/entries")
                        .contentType("application/cbor")
                        .content(cborBytes))
                .andExpect(status().isUnauthorized());
    }
}
