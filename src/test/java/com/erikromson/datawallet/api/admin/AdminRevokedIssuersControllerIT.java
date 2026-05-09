package com.erikromson.datawallet.api.admin;

import com.erikromson.datawallet.api.entry.FixtureIssuerKeyResolver;
import com.erikromson.datawallet.persistence.PostgresTestcontainer;
import com.erikromson.datawallet.security.StubAdminPrincipalResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.HexFormat;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"test", "it"})
@Import({PostgresTestcontainer.class, FixtureIssuerKeyResolver.class})
class AdminRevokedIssuersControllerIT {

    @Autowired private MockMvc mvc;
    @Autowired private JdbcTemplate jdbcTemplate;

    private static final UUID REVOKED_SUBJECT = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final UUID ACTIVE_SUBJECT = UUID.fromString("22222222-2222-2222-2222-222222222222");
    private static final byte[] KEY_ID = HexFormat.of().parseHex("aabbccddeeff00112233445566778899");

    @BeforeEach
    void setUp() {
        jdbcTemplate.update("DELETE FROM directory_records WHERE subject_id IN (?::uuid, ?::uuid)",
                REVOKED_SUBJECT.toString(), ACTIVE_SUBJECT.toString());

        jdbcTemplate.update("""
                INSERT INTO directory_records (record_type, subject_id, key_id, status,
                    valid_from, valid_until, issued_at, parent_key_id, signed_record,
                    pending_revocation, revoked_at)
                VALUES ('issuer', ?::uuid, ?, 'revoked',
                    now()-interval '1 day', now()+interval '1 year', now(),
                    ?, ?, false, now())
                """,
                REVOKED_SUBJECT.toString(), KEY_ID, KEY_ID, new byte[]{1});

        jdbcTemplate.update("""
                INSERT INTO directory_records (record_type, subject_id, key_id, status,
                    valid_from, valid_until, issued_at, parent_key_id, signed_record,
                    pending_revocation)
                VALUES ('issuer', ?::uuid, ?, 'active',
                    now()-interval '1 day', now()+interval '1 year', now(),
                    ?, ?, false)
                """,
                ACTIVE_SUBJECT.toString(), KEY_ID, KEY_ID, new byte[]{2});
    }

    @Test
    void returnsRevokedIssuersOnly() throws Exception {
        mvc.perform(get("/v1/admin/directory/revoked-issuers")
                        .header(StubAdminPrincipalResolver.HEADER, StubAdminPrincipalResolver.HEADER_VALUE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].install_uuid").value(REVOKED_SUBJECT.toString()));
    }

    @Test
    void rejectsWithoutAdminCert() throws Exception {
        mvc.perform(get("/v1/admin/directory/revoked-issuers"))
                .andExpect(status().isUnauthorized());
    }
}
