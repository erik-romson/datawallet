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
@Table(name = "directory_records")
@IdClass(DirectoryRecordEntity.DirectoryRecordId.class)
public class DirectoryRecordEntity {

    @Id
    @Column(name = "record_type", nullable = false)
    private String recordType;

    @Id
    @Column(name = "subject_id", nullable = false)
    private UUID subjectId;

    @Id
    @Column(name = "key_id", nullable = false)
    private byte[] keyId;

    @Column(name = "status", nullable = false)
    private String status;

    @Column(name = "valid_from", nullable = false)
    private Instant validFrom;

    @Column(name = "valid_until", nullable = false)
    private Instant validUntil;

    @Column(name = "issued_at", nullable = false)
    private Instant issuedAt;

    @Column(name = "root_key_id", nullable = true)
    private byte[] rootKeyId;

    @Column(name = "parent_key_id", nullable = true)
    private byte[] parentKeyId;

    @Column(name = "signed_record", nullable = false)
    private byte[] signedRecord;

    @Column(name = "pending_revocation", nullable = false)
    private boolean pendingRevocation;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    protected DirectoryRecordEntity() {}

    public DirectoryRecordEntity(String recordType, UUID subjectId, byte[] keyId,
                                  String status, Instant validFrom, Instant validUntil,
                                  Instant issuedAt, byte[] rootKeyId, byte[] parentKeyId,
                                  byte[] signedRecord) {
        this.recordType = recordType;
        this.subjectId = subjectId;
        this.keyId = keyId;
        this.status = status;
        this.validFrom = validFrom;
        this.validUntil = validUntil;
        this.issuedAt = issuedAt;
        this.rootKeyId = rootKeyId;
        this.parentKeyId = parentKeyId;
        this.signedRecord = signedRecord;
    }

    public String getRecordType() { return recordType; }
    public UUID getSubjectId() { return subjectId; }
    public byte[] getKeyId() { return keyId; }
    public String getStatus() { return status; }
    public Instant getValidFrom() { return validFrom; }
    public Instant getValidUntil() { return validUntil; }
    public Instant getIssuedAt() { return issuedAt; }
    public byte[] getRootKeyId() { return rootKeyId; }
    public byte[] getParentKeyId() { return parentKeyId; }
    public byte[] getSignedRecord() { return signedRecord; }
    public boolean isPendingRevocation() { return pendingRevocation; }
    public Instant getRevokedAt() { return revokedAt; }

    public void setStatus(String status) { this.status = status; }
    public void setValidFrom(Instant validFrom) { this.validFrom = validFrom; }
    public void setValidUntil(Instant validUntil) { this.validUntil = validUntil; }
    public void setIssuedAt(Instant issuedAt) { this.issuedAt = issuedAt; }
    public void setRootKeyId(byte[] rootKeyId) { this.rootKeyId = rootKeyId; }
    public void setParentKeyId(byte[] parentKeyId) { this.parentKeyId = parentKeyId; }
    public void setSignedRecord(byte[] signedRecord) { this.signedRecord = signedRecord; }
    public void setPendingRevocation(boolean pendingRevocation) {
        this.pendingRevocation = pendingRevocation;
    }
    public void setRevokedAt(Instant revokedAt) { this.revokedAt = revokedAt; }

    public static class DirectoryRecordId implements Serializable {
        private String recordType;
        private UUID subjectId;
        private byte[] keyId;

        public DirectoryRecordId() {}

        public DirectoryRecordId(String recordType, UUID subjectId, byte[] keyId) {
            this.recordType = recordType;
            this.subjectId = subjectId;
            this.keyId = keyId;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof DirectoryRecordId that)) return false;
            return Objects.equals(recordType, that.recordType)
                    && Objects.equals(subjectId, that.subjectId)
                    && java.util.Arrays.equals(keyId, that.keyId);
        }

        @Override
        public int hashCode() {
            int result = Objects.hash(recordType, subjectId);
            result = 31 * result + java.util.Arrays.hashCode(keyId);
            return result;
        }
    }
}
