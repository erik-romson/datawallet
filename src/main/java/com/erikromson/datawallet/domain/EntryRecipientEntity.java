package com.erikromson.datawallet.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;

import java.io.Serializable;
import java.util.Objects;
import java.util.UUID;

@Entity
@Table(name = "entry_recipients")
@IdClass(EntryRecipientEntity.EntryRecipientId.class)
public class EntryRecipientEntity {

    @Id
    @Column(name = "entry_id", nullable = false)
    private UUID entryId;

    @Id
    @Column(name = "version", nullable = false)
    private int version;

    @Id
    @Column(name = "verifier_id", nullable = false)
    private UUID verifierId;

    @Column(name = "verifier_key_id", nullable = false)
    private byte[] verifierKeyId;

    protected EntryRecipientEntity() {}

    public EntryRecipientEntity(UUID entryId, int version, UUID verifierId, byte[] verifierKeyId) {
        this.entryId = entryId;
        this.version = version;
        this.verifierId = verifierId;
        this.verifierKeyId = verifierKeyId;
    }

    public UUID getEntryId() { return entryId; }
    public int getVersion() { return version; }
    public UUID getVerifierId() { return verifierId; }
    public byte[] getVerifierKeyId() { return verifierKeyId; }

    public static class EntryRecipientId implements Serializable {
        private UUID entryId;
        private int version;
        private UUID verifierId;

        public EntryRecipientId() {}

        public EntryRecipientId(UUID entryId, int version, UUID verifierId) {
            this.entryId = entryId;
            this.version = version;
            this.verifierId = verifierId;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof EntryRecipientId that)) return false;
            return version == that.version
                    && Objects.equals(entryId, that.entryId)
                    && Objects.equals(verifierId, that.verifierId);
        }

        @Override
        public int hashCode() {
            return Objects.hash(entryId, version, verifierId);
        }
    }
}
