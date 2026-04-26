package com.erikromson.datawallet.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "auth_lockouts")
public class AuthLockoutEntity {

    @Id
    @Column(name = "verifier_id", nullable = false)
    private UUID verifierId;

    @Column(name = "consecutive_failures", nullable = false)
    private int consecutiveFailures;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected AuthLockoutEntity() {}

    public AuthLockoutEntity(UUID verifierId) {
        this.verifierId = verifierId;
        this.consecutiveFailures = 0;
        this.lockedUntil = null;
        this.updatedAt = Instant.now();
    }

    public UUID getVerifierId() { return verifierId; }
    public int getConsecutiveFailures() { return consecutiveFailures; }
    public Instant getLockedUntil() { return lockedUntil; }
    public Instant getUpdatedAt() { return updatedAt; }

    public void setConsecutiveFailures(int consecutiveFailures) { this.consecutiveFailures = consecutiveFailures; }
    public void setLockedUntil(Instant lockedUntil) { this.lockedUntil = lockedUntil; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}
