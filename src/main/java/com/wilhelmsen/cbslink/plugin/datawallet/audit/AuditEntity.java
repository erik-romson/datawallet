package com.wilhelmsen.cbslink.plugin.datawallet.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(name = "audit_log")
public class AuditEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "seq")
    private long seq;

    @Column(name = "ts", nullable = false)
    private Instant ts;

    @Column(name = "event_type", nullable = false)
    private String eventType;

    @Column(name = "actor_id")
    private UUID actorId;

    @Column(name = "entry_id")
    private UUID entryId;

    @Column(name = "payload", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> payload;

    @Column(name = "prev_hash")
    private byte[] prevHash;

    @Column(name = "hash")
    private byte[] hash;

    protected AuditEntity() {}

    public AuditEntity(Instant ts, String eventType, UUID actorId, UUID entryId,
                       Map<String, Object> payload, byte[] prevHash, byte[] hash) {
        this.ts = ts;
        this.eventType = eventType;
        this.actorId = actorId;
        this.entryId = entryId;
        this.payload = payload;
        this.prevHash = prevHash;
        this.hash = hash;
    }

    public long getSeq() { return seq; }
    public Instant getTs() { return ts; }
    public String getEventType() { return eventType; }
    public UUID getActorId() { return actorId; }
    public UUID getEntryId() { return entryId; }
    public Map<String, Object> getPayload() { return payload; }
    public byte[] getPrevHash() { return prevHash; }
    public byte[] getHash() { return hash; }
}
