package com.erikromson.datawallet.api.admin;

import com.erikromson.datawallet.api.entry.FixtureIssuerKeyResolver;
import com.erikromson.datawallet.persistence.PostgresTestcontainer;
import com.erikromson.datawallet.security.StubAdminPrincipalResolver;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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

import java.util.HexFormat;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"test", "it"})
@Import({PostgresTestcontainer.class, FixtureIssuerKeyResolver.class})
class AdminActiveIssuersControllerIT {

    @Autowired private MockMvc mvc;
    @Autowired private JdbcTemplate jdbcTemplate;
    @Autowired private ObjectMapper objectMapper;

    private static final UUID ACTIVE_1 = UUID.fromString("aa000001-0000-0000-0000-000000000001");
    private static final UUID ACTIVE_2 = UUID.fromString("aa000002-0000-0000-0000-000000000002");
    private static final UUID ACTIVE_3 = UUID.fromString("aa000003-0000-0000-0000-000000000003");
    private static final UUID SUPERSEDED = UUID.fromString("bb000001-0000-0000-0000-000000000001");
    private static final UUID PENDING = UUID.fromString("cc000001-0000-0000-0000-000000000001");
    private static final UUID VERIFIER = UUID.fromString("dd000001-0000-0000-0000-000000000001");
    private static final byte[] KEY_ID = HexFormat.of().parseHex("aabbccddeeff00112233445566778899");

    @BeforeEach
    void setUp() {
        jdbcTemplate.update("""
                DELETE FROM directory_records WHERE subject_id IN (
                    ?::uuid, ?::uuid, ?::uuid, ?::uuid, ?::uuid, ?::uuid
                )
                """,
                ACTIVE_1.toString(), ACTIVE_2.toString(), ACTIVE_3.toString(),
                SUPERSEDED.toString(), PENDING.toString(), VERIFIER.toString());

        // three eligible: active issuer, no pending_revocation, staggered issued_at for stable ordering
        insertIssuer(ACTIVE_1, "active", false, "now() - interval '5 seconds'");
        insertIssuer(ACTIVE_2, "active", false, "now() - interval '3 seconds'");
        insertIssuer(ACTIVE_3, "active", false, "now() - interval '1 second'");

        // superseded issuer — must be excluded (non-active status)
        insertIssuer(SUPERSEDED, "superseded", false, "now() - interval '4 seconds'");

        // active issuer with pending_revocation=true — must be excluded
        insertIssuer(PENDING, "active", true, "now() - interval '2 seconds'");

        // verifier record — must be excluded regardless of status
        insertRecord("verifier", VERIFIER, "active", false, "now() - interval '2 seconds'");
    }

    @Test
    void returnsOnlyEligibleIssuers() throws Exception {
        MvcResult result = mvc.perform(get("/v1/admin/directory/active-issuers")
                        .header(StubAdminPrincipalResolver.HEADER, StubAdminPrincipalResolver.HEADER_VALUE))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        JsonNode items = body.get("items");

        Set<String> returnedIds = new HashSet<>();
        for (JsonNode item : items) {
            returnedIds.add(item.get("subject_id").asText());
        }

        assertThat(returnedIds).containsExactlyInAnyOrder(
                ACTIVE_1.toString(), ACTIVE_2.toString(), ACTIVE_3.toString());
        assertThat(returnedIds).doesNotContain(
                SUPERSEDED.toString(), PENDING.toString(), VERIFIER.toString());
    }

    @Test
    void excludesPendingRevocation() throws Exception {
        mvc.perform(get("/v1/admin/directory/active-issuers")
                        .header(StubAdminPrincipalResolver.HEADER, StubAdminPrincipalResolver.HEADER_VALUE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items[?(@.subject_id == '" + PENDING + "')]").isEmpty());
    }

    @Test
    void paginationRoundTrip() throws Exception {
        // page 1: limit=2 → 2 items + cursor
        MvcResult page1Result = mvc.perform(get("/v1/admin/directory/active-issuers")
                        .param("limit", "2")
                        .header(StubAdminPrincipalResolver.HEADER, StubAdminPrincipalResolver.HEADER_VALUE))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode page1 = objectMapper.readTree(page1Result.getResponse().getContentAsString());
        assertThat(page1.get("items").size()).isEqualTo(2);
        JsonNode cursorNode = page1.get("next_cursor");
        assertThat(cursorNode).isNotNull();
        assertThat(cursorNode.isNull()).isFalse();
        String nextCursor = cursorNode.asText();

        // page 2 via cursor → 1 remaining item, no more cursor
        MvcResult page2Result = mvc.perform(get("/v1/admin/directory/active-issuers")
                        .param("limit", "2")
                        .param("cursor", nextCursor)
                        .header(StubAdminPrincipalResolver.HEADER, StubAdminPrincipalResolver.HEADER_VALUE))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode page2 = objectMapper.readTree(page2Result.getResponse().getContentAsString());
        assertThat(page2.get("items").size()).isEqualTo(1);
        assertThat(page2.get("next_cursor").isNull()).isTrue();

        // both pages together cover exactly the 3 eligible issuers, no overlap
        Set<String> seen = new HashSet<>();
        for (JsonNode item : page1.get("items")) seen.add(item.get("subject_id").asText());
        for (JsonNode item : page2.get("items")) seen.add(item.get("subject_id").asText());
        assertThat(seen).containsExactlyInAnyOrder(
                ACTIVE_1.toString(), ACTIVE_2.toString(), ACTIVE_3.toString());
    }

    @Test
    void excludesNonIssuerRecords() throws Exception {
        mvc.perform(get("/v1/admin/directory/active-issuers")
                        .header(StubAdminPrincipalResolver.HEADER, StubAdminPrincipalResolver.HEADER_VALUE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items[?(@.subject_id == '" + VERIFIER + "')]").isEmpty());
    }

    @Test
    void rejectsWithoutAdminCert() throws Exception {
        mvc.perform(get("/v1/admin/directory/active-issuers"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void dtoFieldsPresent() throws Exception {
        MvcResult result = mvc.perform(get("/v1/admin/directory/active-issuers")
                        .header(StubAdminPrincipalResolver.HEADER, StubAdminPrincipalResolver.HEADER_VALUE))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode item = objectMapper.readTree(result.getResponse().getContentAsString())
                .get("items").get(0);

        assertThat(item.has("subject_id")).isTrue();
        assertThat(item.has("key_id")).isTrue();
        assertThat(item.has("valid_from")).isTrue();
        assertThat(item.has("valid_until")).isTrue();
        assertThat(item.has("issued_at")).isTrue();
        assertThat(item.has("signed_record")).isTrue();
    }

    private void insertIssuer(UUID subjectId, String status, boolean pendingRevocation, String issuedAtExpr) {
        insertRecord("issuer", subjectId, status, pendingRevocation, issuedAtExpr);
    }

    private void insertRecord(String recordType, UUID subjectId, String status,
                               boolean pendingRevocation, String issuedAtExpr) {
        jdbcTemplate.update("""
                INSERT INTO directory_records (record_type, subject_id, key_id, status,
                    valid_from, valid_until, issued_at, parent_key_id, signed_record, pending_revocation)
                VALUES (?, ?::uuid, ?, ?, now()-interval '1 day', now()+interval '1 year',
                    %s, ?, ?, ?)
                """.formatted(issuedAtExpr),
                recordType, subjectId.toString(), KEY_ID, status, KEY_ID, new byte[]{1}, pendingRevocation);
    }
}
