package com.erikromson.datawallet.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "rate_limits")
public class RateLimitEntity {

    @Id
    @Column(name = "key", nullable = false)
    private String key;

    @Column(name = "tokens", nullable = false)
    private double tokens;

    @Column(name = "refilled_at", nullable = false)
    private Instant refilledAt;

    protected RateLimitEntity() {}

    public RateLimitEntity(String key, double tokens, Instant refilledAt) {
        this.key = key;
        this.tokens = tokens;
        this.refilledAt = refilledAt;
    }

    public String getKey() { return key; }
    public double getTokens() { return tokens; }
    public Instant getRefilledAt() { return refilledAt; }

    public void setTokens(double tokens) { this.tokens = tokens; }
    public void setRefilledAt(Instant refilledAt) { this.refilledAt = refilledAt; }
}
