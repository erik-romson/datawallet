package com.wilhelmsen.cbslink.plugin.datawallet.audit;

import com.wilhelmsen.cbslink.plugin.datawallet.crypto.CanonicalCborMapper;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.Sha256;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Real hash-chain implementation of {@link AuditService}.
 *
 * <p>Computes {@code hash_n = SHA256(prev_hash || canonical_cbor(event))} per
 * `crypto-formats.md §11`. Each event is written in a dedicated {@code REQUIRES_NEW}
 * transaction so the audit record commits independently of the caller's transaction.
 * The {@code FOR UPDATE} on the chain-head read serializes concurrent writers.
 *
 * <p>v1 chain insert is a serialization point; pilot scale tolerates this.
 * Future scale needs partitioned chains.
 */
@Service
@Primary
public class HashChainAuditService implements AuditService {

    static final byte[] GENESIS_PREV_HASH;

    static {
        byte[] seed = "datawallet-audit-genesis-v1\0".getBytes(StandardCharsets.UTF_8);
        GENESIS_PREV_HASH = Sha256.hash(seed);
    }

    private final AuditRepository auditRepository;
    private final CanonicalCborMapper cborMapper;

    public HashChainAuditService(AuditRepository auditRepository) {
        this.auditRepository = auditRepository;
        this.cborMapper = new CanonicalCborMapper();
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordEvent(EventType type, UUID actorId, UUID entryId, Map<String, Object> payload) {
        Optional<AuditEntity> head = auditRepository.findHeadForUpdate();

        long nextSeq = head.map(h -> h.getSeq() + 1).orElse(1L);
        byte[] prevHash = head.map(AuditEntity::getHash).orElse(GENESIS_PREV_HASH);

        // Truncate to milliseconds so the TIMESTAMPTZ round-trip does not shift the ts value
        // used in the hash (Postgres microsecond precision would otherwise cause sub-ms drift).
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        byte[] eventCanonical = buildEventCanonical(
                nextSeq, now, type.name().toLowerCase(), actorId, entryId, payload);
        byte[] hash = sha256concat(prevHash, eventCanonical);

        auditRepository.save(new AuditEntity(
                now, type.name().toLowerCase(), actorId, entryId, payload, prevHash, hash));
    }

    @Override
    public Optional<ChainHead> head() {
        return auditRepository.findTopByOrderBySeqDesc()
                .map(e -> new ChainHead(e.getSeq(), e.getHash()));
    }

    byte[] buildEventCanonical(long seq, Instant ts, String eventType,
                                UUID actorId, UUID entryId, Map<String, Object> payload) {
        Map<String, Object> map = new HashMap<>();
        map.put("seq", seq);
        map.put("ts", ts.toEpochMilli());
        map.put("event_type", eventType);
        map.put("actor_id", actorId != null ? uuidToBytes(actorId) : null);
        map.put("entry_id", entryId != null ? uuidToBytes(entryId) : null);
        map.put("payload", payload != null ? payload : Map.of());
        return cborMapper.writeBytes(map);
    }

    static byte[] uuidToBytes(UUID uuid) {
        ByteBuffer buf = ByteBuffer.wrap(new byte[16]);
        buf.putLong(uuid.getMostSignificantBits());
        buf.putLong(uuid.getLeastSignificantBits());
        return buf.array();
    }

    static byte[] sha256concat(byte[] a, byte[] b) {
        byte[] combined = new byte[a.length + b.length];
        System.arraycopy(a, 0, combined, 0, a.length);
        System.arraycopy(b, 0, combined, a.length, b.length);
        return Sha256.hash(combined);
    }
}
