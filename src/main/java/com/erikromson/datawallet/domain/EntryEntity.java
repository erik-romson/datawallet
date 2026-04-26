package com.erikromson.datawallet.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;

import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

@Entity
@Table(name = "entries")
@IdClass(EntryEntity.EntryId.class)
public class EntryEntity {

    @Id
    @Column(name = "entry_id", nullable = false)
    private UUID entryId;

    @Id
    @Column(name = "version", nullable = false)
    private int version;

    @Column(name = "issuer_id", nullable = false)
    private UUID issuerId;

    @Column(name = "is_current", nullable = false)
    private boolean isCurrent;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "superseded_at")
    private Instant supersededAt;

    @Column(name = "signed_envelope", nullable = false)
    private byte[] signedEnvelope;

    @Column(name = "ciphertext_hash", nullable = false)
    private byte[] ciphertextHash;

    @Column(name = "issuer_label")
    private String issuerLabel;

    @Column(name = "issuer_signing_key_id")
    private byte[] issuerSigningKeyId;

    @Column(name = "description")
    private String description;

    protected EntryEntity() {}

    public EntryEntity(UUID entryId, int version, UUID issuerId, boolean isCurrent,
                       Instant createdAt, Instant supersededAt,
                       byte[] signedEnvelope, byte[] ciphertextHash,
                       String issuerLabel, byte[] issuerSigningKeyId, String description) {
        this.entryId = entryId;
        this.version = version;
        this.issuerId = issuerId;
        this.isCurrent = isCurrent;
        this.createdAt = createdAt;
        this.supersededAt = supersededAt;
        this.signedEnvelope = signedEnvelope;
        this.ciphertextHash = ciphertextHash;
        this.issuerLabel = issuerLabel;
        this.issuerSigningKeyId = issuerSigningKeyId;
        this.description = description;
    }

    public UUID getEntryId() { return entryId; }
    public int getVersion() { return version; }
    public UUID getIssuerId() { return issuerId; }
    public boolean isCurrent() { return isCurrent; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getSupersededAt() { return supersededAt; }
    public byte[] getSignedEnvelope() { return signedEnvelope; }
    public byte[] getCiphertextHash() { return ciphertextHash; }
    public String getIssuerLabel() { return issuerLabel; }
    public byte[] getIssuerSigningKeyId() { return issuerSigningKeyId; }
    public String getDescription() { return description; }

    public void setCurrent(boolean current) { this.isCurrent = current; }
    public void setSupersededAt(Instant supersededAt) { this.supersededAt = supersededAt; }

    public static class EntryId implements Serializable {
        private UUID entryId;
        private int version;

        public EntryId() {}

        public EntryId(UUID entryId, int version) {
            this.entryId = entryId;
            this.version = version;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof EntryId that)) return false;
            return version == that.version && Objects.equals(entryId, that.entryId);
        }

        @Override
        public int hashCode() {
            return Objects.hash(entryId, version);
        }
    }
}
