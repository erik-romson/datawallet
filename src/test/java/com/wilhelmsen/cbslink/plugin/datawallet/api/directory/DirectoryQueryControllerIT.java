package com.wilhelmsen.cbslink.plugin.datawallet.api.directory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wilhelmsen.cbslink.plugin.datawallet.api.entry.FixtureIssuerKeyResolver;
import com.wilhelmsen.cbslink.plugin.datawallet.persistence.PostgresTestcontainer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"test", "it"})
@Import({PostgresTestcontainer.class, FixtureIssuerKeyResolver.class})
class DirectoryQueryControllerIT {

    @Autowired private MockMvc mvc;
    @Autowired private JdbcTemplate jdbcTemplate;

    private static final String TEST_HANDLE = "dirqtest";
    private UUID testVerifierId;
    private UUID testIssuerId;
    private static final byte[] DUMMY_KEY_ID = new byte[16];
    private static final byte[] DUMMY_ROOT_KEY_ID = new byte[16];
    private static final byte[] DUMMY_SIGNED_RECORD = new byte[]{0x01, 0x02};

    @BeforeEach
    void setUp() {
        testVerifierId = UUID.randomUUID();
        testIssuerId = UUID.randomUUID();

        // Register a verifier with the test handle
        jdbcTemplate.update("""
                INSERT INTO verifiers (verifier_id, handle, enc_public_key, enc_key_id, auth_public_key,
                    auth_key_id, wrapped_enc_private_key_blob, wrapped_auth_private_key_blob, kdf_salt, kdf_params)
                VALUES (?::uuid, ?, ?, ?, ?, ?, ?, ?, ?,
                    '{"alg":"argon2id","m":268435456,"t":3,"p":1,"version":19}'::jsonb)
                """,
                testVerifierId.toString(), TEST_HANDLE,
                new byte[32], new byte[16], new byte[32], new byte[16],
                new byte[48], new byte[48], new byte[16]);

        // Insert a directory record for the verifier
        jdbcTemplate.update("""
                INSERT INTO directory_records (record_type, subject_id, key_id, status,
                    valid_from, valid_until, issued_at, root_key_id, signed_record, pending_revocation)
                VALUES ('verifier', ?::uuid, ?, 'active',
                    now()-interval '1 day', now()+interval '1 year', now(), ?, ?, false)
                """,
                testVerifierId.toString(), DUMMY_KEY_ID, DUMMY_ROOT_KEY_ID, DUMMY_SIGNED_RECORD);

        // Insert a directory record for the issuer
        jdbcTemplate.update("""
                INSERT INTO directory_records (record_type, subject_id, key_id, status,
                    valid_from, valid_until, issued_at, root_key_id, signed_record, pending_revocation)
                VALUES ('issuer', ?::uuid, ?, 'active',
                    now()-interval '1 day', now()+interval '1 year', now(), ?, ?, false)
                """,
                testIssuerId.toString(), DUMMY_KEY_ID, DUMMY_ROOT_KEY_ID, DUMMY_SIGNED_RECORD);
    }

    @AfterEach
    void tearDown() {
        jdbcTemplate.update("DELETE FROM directory_records WHERE subject_id IN (?::uuid, ?::uuid)",
                testVerifierId.toString(), testIssuerId.toString());
        jdbcTemplate.update("DELETE FROM verifiers WHERE verifier_id = ?::uuid", testVerifierId.toString());
    }

    @Test
    void getVerifier_returnsActiveRecords() throws Exception {
        mvc.perform(get("/v1/directory/verifiers/" + TEST_HANDLE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.records").isArray())
                .andExpect(jsonPath("$.records[0].status").value("active"))
                .andExpect(jsonPath("$.records[0].signed_record").isString());
    }

    @Test
    void getVerifier_nonExistentHandle_returns404() throws Exception {
        mvc.perform(get("/v1/directory/verifiers/no-such-handle"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("handle_not_found"));
    }

    @Test
    void getIssuer_returnsActiveRecords() throws Exception {
        mvc.perform(get("/v1/directory/issuers/" + testIssuerId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.records").isArray())
                .andExpect(jsonPath("$.records[0].status").value("active"))
                .andExpect(jsonPath("$.records[0].signed_record").isString());
    }

    @Test
    void getIssuer_nonExistent_returns404() throws Exception {
        mvc.perform(get("/v1/directory/issuers/" + UUID.randomUUID()))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("issuer_not_found"));
    }

    @Test
    void getRoot_returnsPinnedRootKeys() throws Exception {
        mvc.perform(get("/v1/directory/root"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roots").isArray())
                .andExpect(jsonPath("$.roots[0].root_key_id").isString())
                .andExpect(jsonPath("$.roots[0].public_key").isString())
                .andExpect(jsonPath("$.roots[0].status").value("active"));
    }
}
