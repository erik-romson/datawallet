package com.wilhelmsen.cbslink.plugin.datawallet.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "sessions")
public class SessionEntity {

    @Id
    @Column(name = "token_id", nullable = false)
    private byte[] tokenId;

    @Column(name = "verifier_id", nullable = false)
    private UUID verifierId;

    @Column(name = "issued_at", nullable = false)
    private Instant issuedAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    protected SessionEntity() {}

    public SessionEntity(byte[] tokenId, UUID verifierId, Instant issuedAt, Instant expiresAt) {
        this.tokenId = tokenId;
        this.verifierId = verifierId;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
    }

    public byte[] getTokenId() { return tokenId; }
    public UUID getVerifierId() { return verifierId; }
    public Instant getIssuedAt() { return issuedAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public Instant getRevokedAt() { return revokedAt; }

    public void setRevokedAt(Instant revokedAt) { this.revokedAt = revokedAt; }
}
