package com.erikromson.datawallet.api.admin;

import com.erikromson.datawallet.api.entry.FixtureIssuerKeyResolver;
import com.erikromson.datawallet.audit.AuditRepository;
import com.erikromson.datawallet.audit.AuditService;
import com.erikromson.datawallet.persistence.PostgresTestcontainer;
import com.erikromson.datawallet.security.StubAdminPrincipalResolver;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"test", "it"})
@Import({PostgresTestcontainer.class, FixtureIssuerKeyResolver.class})
class AdminAuditControllerIT {

    @Autowired private MockMvc mvc;
    @Autowired private AuditService auditService;
    @Autowired private AuditRepository auditRepository;

    @Test
    void headQuery_returnsChainHead() throws Exception {
        // Seed an event so there is at least one row
        auditService.recordEvent(AuditService.EventType.VERIFIER_REGISTERED, UUID.randomUUID(), null,
                Map.of("handle", "audit-head-test-" + UUID.randomUUID()));

        mvc.perform(get("/v1/admin/audit")
                        .param("head", "true")
                        .header(StubAdminPrincipalResolver.HEADER, StubAdminPrincipalResolver.HEADER_VALUE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.head.seq").isNumber())
                .andExpect(jsonPath("$.head.hash").isString());
    }

    @Test
    void pageQuery_returnsPaginatedItems() throws Exception {
        long seqBefore = auditRepository.findTopByOrderBySeqDesc()
                .map(e -> e.getSeq())
                .orElse(0L);

        UUID actor = UUID.randomUUID();
        auditService.recordEvent(AuditService.EventType.ENTRY_CREATED, actor, UUID.randomUUID(),
                Map.of("version", 1, "tag", "page-query-test-" + actor));
        auditService.recordEvent(AuditService.EventType.ENTRY_UPDATED, actor, UUID.randomUUID(),
                Map.of("version", 2, "tag", "page-query-test-" + actor));

        mvc.perform(get("/v1/admin/audit")
                        .param("since_seq", String.valueOf(seqBefore))
                        .param("limit", "10")
                        .header(StubAdminPrincipalResolver.HEADER, StubAdminPrincipalResolver.HEADER_VALUE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items").isArray())
                .andExpect(jsonPath("$.items[0].seq").isNumber())
                .andExpect(jsonPath("$.items[0].event_type").isString());
    }

    @Test
    void withoutAdminPrincipal_returns401() throws Exception {
        mvc.perform(get("/v1/admin/audit").param("head", "true"))
                .andExpect(status().isUnauthorized());
    }
}
