package com.erikromson.datawallet.audit;

import com.erikromson.datawallet.persistence.PostgresTestcontainer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@ActiveProfiles("test")
@Import(PostgresTestcontainer.class)
class AuditAppendOnlyIT {

    @Autowired private AuditService auditService;
    @Autowired private AuditRepository auditRepository;
    @Autowired private JdbcTemplate jdbcTemplate;

    @Test
    void updateBlockedByTrigger() {
        auditService.recordEvent(AuditService.EventType.VERIFIER_REGISTERED,
                UUID.randomUUID(), null, Map.of("test", "update-block"));

        List<AuditEntity> rows = auditRepository.findAllByOrderBySeqAsc();
        long seq = rows.get(0).getSeq();

        assertThatThrownBy(() ->
                jdbcTemplate.update("UPDATE audit_log SET event_type = 'tampered' WHERE seq = ?", seq))
                .isInstanceOf(DataAccessException.class)
                .hasMessageContaining("audit_log is append-only");
    }

    @Test
    void deleteBlockedByTrigger() {
        auditService.recordEvent(AuditService.EventType.VERIFIER_LOGIN,
                UUID.randomUUID(), null, Map.of("test", "delete-block"));

        List<AuditEntity> rows = auditRepository.findAllByOrderBySeqAsc();
        long seq = rows.get(rows.size() - 1).getSeq();

        assertThatThrownBy(() ->
                jdbcTemplate.update("DELETE FROM audit_log WHERE seq = ?", seq))
                .isInstanceOf(DataAccessException.class)
                .hasMessageContaining("audit_log is append-only");
    }

    @Test
    void readsAndHeadSucceed() {
        auditService.recordEvent(AuditService.EventType.VERIFIER_LOGOUT,
                UUID.randomUUID(), null, Map.of());

        assertThat(auditRepository.findAllByOrderBySeqAsc()).isNotEmpty();
        assertThat(auditService.head()).isPresent();
    }
}
