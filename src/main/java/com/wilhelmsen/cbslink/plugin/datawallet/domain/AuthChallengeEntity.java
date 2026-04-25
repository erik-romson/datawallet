package com.wilhelmsen.cbslink.plugin.datawallet.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;

import java.io.Serializable;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

@Entity
@Table(name = "auth_challenges")
@IdClass(AuthChallengeEntity.PK.class)
public class AuthChallengeEntity {

    @Id
    @Column(name = "verifier_id", nullable = false)
    private UUID verifierId;

    @Id
    @Column(name = "nonce", nullable = false)
    private byte[] nonce;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "consumed_at")
    private Instant consumedAt;

    protected AuthChallengeEntity() {}

    public AuthChallengeEntity(UUID verifierId, byte[] nonce, Instant createdAt, Instant expiresAt) {
        this.verifierId = verifierId;
        this.nonce = nonce;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
    }

    public UUID getVerifierId() { return verifierId; }
    public byte[] getNonce() { return nonce; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public Instant getConsumedAt() { return consumedAt; }

    public void setConsumedAt(Instant consumedAt) { this.consumedAt = consumedAt; }

    public static class PK implements Serializable {
        private UUID verifierId;
        private byte[] nonce;

        public PK() {}

        public PK(UUID verifierId, byte[] nonce) {
            this.verifierId = verifierId;
            this.nonce = nonce;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof PK pk)) return false;
            return Objects.equals(verifierId, pk.verifierId) && Arrays.equals(nonce, pk.nonce);
        }

        @Override
        public int hashCode() {
            return Objects.hash(verifierId, Arrays.hashCode(nonce));
        }
    }
}
