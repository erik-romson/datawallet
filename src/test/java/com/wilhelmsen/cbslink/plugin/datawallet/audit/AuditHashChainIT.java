package com.wilhelmsen.cbslink.plugin.datawallet.audit;

import com.wilhelmsen.cbslink.plugin.datawallet.crypto.CanonicalCborMapper;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.Sha256;
import com.wilhelmsen.cbslink.plugin.datawallet.persistence.PostgresTestcontainer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
@Import(PostgresTestcontainer.class)
class AuditHashChainIT {

    private static final String GENESIS_PREV_HASH_HEX =
            "fbefdf53b83194aa165dcf812120fa6e0d10691470d3e1a039d07cbccd04ebf4";

    @Autowired private AuditService auditService;
    @Autowired private AuditRepository auditRepository;
    @Autowired private JdbcTemplate jdbcTemplate;

    private final CanonicalCborMapper cborMapper = new CanonicalCborMapper();

    @Test
    void activeServiceIsHashChainImplementation() {
        assertThat(auditService).isInstanceOf(HashChainAuditService.class);
    }

    @Test
    void genesisHashMatchesFixture() {
        byte[] seed = "datawallet-audit-genesis-v1\0".getBytes(StandardCharsets.UTF_8);
        byte[] computed = Sha256.hash(seed);
        assertThat(HexFormat.of().formatHex(computed)).isEqualTo(GENESIS_PREV_HASH_HEX);
    }

    @Test
    void chainFormsValidHashChain() {
        UUID actor1 = UUID.randomUUID();
        UUID actor2 = UUID.randomUUID();
        UUID entry1 = UUID.randomUUID();

        auditService.recordEvent(AuditService.EventType.VERIFIER_REGISTERED, actor1, null,
                Map.of("handle", "chain-test-user"));
        auditService.recordEvent(AuditService.EventType.ENTRY_CREATED, actor2, entry1,
                Map.of("version", 1));
        auditService.recordEvent(AuditService.EventType.ENTRY_UPDATED, actor2, entry1,
                Map.of("version", 2));

        List<AuditEntity> rows = auditRepository.findAllByOrderBySeqAsc();
        assertThat(rows).isNotEmpty();

        // seq=1 must carry the genesis prev_hash
        AuditEntity first = rows.get(0);
        assertThat(HexFormat.of().formatHex(first.getPrevHash()))
                .as("genesis prev_hash")
                .isEqualTo(GENESIS_PREV_HASH_HEX);

        // Every row: prev_hash links to predecessor, hash = SHA256(prev_hash || canonical)
        byte[] expectedPrev = HashChainAuditService.GENESIS_PREV_HASH;
        for (AuditEntity row : rows) {
            assertThat(row.getPrevHash())
                    .as("prev_hash linkage at seq=%d", row.getSeq())
                    .isEqualTo(expectedPrev);

            byte[] canonical = buildCanonical(row);
            byte[] expectedHash = HashChainAuditService.sha256concat(row.getPrevHash(), canonical);
            assertThat(row.getHash())
                    .as("hash integrity at seq=%d", row.getSeq())
                    .isEqualTo(expectedHash);

            expectedPrev = row.getHash();
        }
    }

    @Test
    void tamperDetectedWhenPayloadMutated() {
        UUID actor = UUID.randomUUID();
        auditService.recordEvent(AuditService.EventType.VERIFIER_LOGIN, actor, null,
                Map.of("ip", "127.0.0.1"));

        List<AuditEntity> rows = auditRepository.findAllByOrderBySeqAsc();
        AuditEntity target = rows.get(rows.size() - 1);
        long seq = target.getSeq();

        // Disable trigger so the test can mutate the row (test user owns the table)
        jdbcTemplate.execute("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update_or_delete");
        try {
            jdbcTemplate.update(
                    "UPDATE audit_log SET payload = '{\"ip\": \"tampered\"}'::jsonb WHERE seq = ?", seq);

            AuditEntity tampered = auditRepository.findById(seq).orElseThrow();
            byte[] recomputed = HashChainAuditService.sha256concat(
                    tampered.getPrevHash(), buildCanonical(tampered));
            // Stored hash was computed from original payload; recomputed uses tampered payload
            assertThat(recomputed)
                    .as("tampered hash must not match stored hash")
                    .isNotEqualTo(tampered.getHash());

            // Restore original payload so the chain remains intact for other tests
            jdbcTemplate.update(
                    "UPDATE audit_log SET payload = '{\"ip\": \"127.0.0.1\"}'::jsonb WHERE seq = ?", seq);
        } finally {
            jdbcTemplate.execute("ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_update_or_delete");
        }
    }

    private byte[] buildCanonical(AuditEntity row) {
        Map<String, Object> map = new HashMap<>();
        map.put("seq", row.getSeq());
        map.put("ts", row.getTs().toEpochMilli());
        map.put("event_type", row.getEventType());
        map.put("actor_id", row.getActorId() != null
                ? HashChainAuditService.uuidToBytes(row.getActorId()) : null);
        map.put("entry_id", row.getEntryId() != null
                ? HashChainAuditService.uuidToBytes(row.getEntryId()) : null);
        map.put("payload", row.getPayload() != null ? row.getPayload() : Map.of());
        return cborMapper.writeBytes(map);
    }
}
