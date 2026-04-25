package com.wilhelmsen.cbslink.plugin.datawallet.persistence;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@ActiveProfiles("test")
@Import(PostgresTestcontainer.class)
class SchemaIntegrationTest {

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    void allTablesExist() {
        List<String> tables = jdbc.queryForList(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'",
                String.class
        );
        assertThat(tables).containsExactlyInAnyOrder(
                "verifiers",
                "entries",
                "entry_recipients",
                "directory_records",
                "sessions",
                "audit_log",
                "auth_challenges",
                "auth_lockouts",
                "rate_limits",
                "pinned_root_history",
                "flyway_schema_history"
        );
    }

    @Test
    void auditLogTriggerExists() {
        Integer count = jdbc.queryForObject(
                "SELECT COUNT(*) FROM pg_trigger WHERE tgname = 'audit_log_no_update_or_delete'",
                Integer.class
        );
        assertThat(count).isEqualTo(1);
    }

    @Test
    void rolesExist() {
        List<String> roles = jdbc.queryForList(
                "SELECT rolname FROM pg_roles WHERE rolname IN ('wallet_app', 'wallet_admin') ORDER BY rolname",
                String.class
        );
        assertThat(roles).containsExactly("wallet_admin", "wallet_app");
    }

    @Test
    void auditLogBlocksUpdate() {
        jdbc.execute("INSERT INTO audit_log (ts, event_type, payload) VALUES (now(), 'test_event', '{}'::jsonb)");

        assertThatThrownBy(() ->
                jdbc.execute("UPDATE audit_log SET event_type = 'tampered' WHERE seq = 1")
        ).hasMessageContaining("audit_log is append-only");
    }

    @Test
    void auditLogBlocksDelete() {
        jdbc.execute("INSERT INTO audit_log (ts, event_type, payload) VALUES (now(), 'test_event', '{}'::jsonb)");

        assertThatThrownBy(() ->
                jdbc.execute("DELETE FROM audit_log WHERE seq = 1")
        ).hasMessageContaining("audit_log is append-only");
    }
}
