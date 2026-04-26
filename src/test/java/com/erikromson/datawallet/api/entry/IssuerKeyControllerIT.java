package com.erikromson.datawallet.api.entry;

import com.erikromson.datawallet.crypto.Random;
import com.erikromson.datawallet.domain.DirectoryRecordEntity;
import com.erikromson.datawallet.domain.DirectoryRecordRepository;
import com.erikromson.datawallet.persistence.PostgresTestcontainer;
import com.erikromson.datawallet.security.HeaderIssuerPrincipalResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

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
@ActiveProfiles({"test", "it"})
@Import({PostgresTestcontainer.class, FixtureIssuerKeyResolver.class})
class IssuerKeyControllerIT {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    @Autowired private MockMvc mvc;
    @Autowired private DirectoryRecordRepository directoryRecordRepository;

    private UUID testIssuerId;
    private byte[] testKeyId;

    @BeforeEach
    void setup() {
        directoryRecordRepository.deleteAll();
        testIssuerId = UUID.randomUUID();
        testKeyId = Random.bytes(16);
        insertActiveRecord(testIssuerId, testKeyId);
    }

    @Test
    void mismatchedPrincipal_returns403() throws Exception {
        UUID differentIssuer = UUID.randomUUID();
        String dto = rotationDto(testKeyId);

        mvc.perform(post("/v1/issuers/" + testIssuerId + "/rotate-signing-key")
                        .header(HeaderIssuerPrincipalResolver.HEADER, differentIssuer.toString())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(dto))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error.code").value("issuer_rotation_forbidden"));
    }

    @Test
    void staleOldKeyId_returns422() throws Exception {
        byte[] unknownKeyId = Random.bytes(16);
        String dto = rotationDto(unknownKeyId);

        mvc.perform(post("/v1/issuers/" + testIssuerId + "/rotate-signing-key")
                        .header(HeaderIssuerPrincipalResolver.HEADER, testIssuerId.toString())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(dto))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error.code").value("key_rotation_stale"));
    }

    @Test
    void happyPath_marksOldKeyPendingRevocation() throws Exception {
        byte[] newKeyId = Random.bytes(16);
        String dto = rotationDto(testKeyId, newKeyId);

        mvc.perform(post("/v1/issuers/" + testIssuerId + "/rotate-signing-key")
                        .header(HeaderIssuerPrincipalResolver.HEADER, testIssuerId.toString())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(dto))
                .andExpect(status().isNoContent());

        List<DirectoryRecordEntity> records =
                directoryRecordRepository.findBySubjectIdAndKeyId(testIssuerId, testKeyId);
        assertThat(records).hasSize(1);
        assertThat(records.getFirst().isPendingRevocation()).isTrue();
    }

    @Test
    void missingPrincipalHeader_returns401() throws Exception {
        String dto = rotationDto(testKeyId);

        mvc.perform(post("/v1/issuers/" + testIssuerId + "/rotate-signing-key")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(dto))
                .andExpect(status().isUnauthorized());
    }

    // --- helpers ---

    private void insertActiveRecord(UUID issuerId, byte[] keyId) {
        DirectoryRecordEntity entity = new DirectoryRecordEntity(
                "issuer", issuerId, keyId, "active",
                Instant.now().minusSeconds(3600),
                Instant.now().plusSeconds(3600),
                Instant.now(),
                new byte[16],
                new byte[32]
        );
        directoryRecordRepository.save(entity);
    }

    private String rotationDto(byte[] oldKeyId) {
        return rotationDto(oldKeyId, Random.bytes(16));
    }

    private String rotationDto(byte[] oldKeyId, byte[] newKeyId) {
        return """
                {
                  "new_public_key": "%s",
                  "new_key_id": "%s",
                  "old_key_id": "%s"
                }
                """.formatted(
                B64URL.encodeToString(new byte[32]),
                B64URL.encodeToString(newKeyId),
                B64URL.encodeToString(oldKeyId)
        );
    }
}
