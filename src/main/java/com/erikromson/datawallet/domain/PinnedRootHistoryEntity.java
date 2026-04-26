package com.erikromson.datawallet.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "pinned_root_history")
public class PinnedRootHistoryEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private long id;

    @Column(name = "applied_at", nullable = false)
    private Instant appliedAt;

    @Column(name = "pinned_root_cbor", nullable = false)
    private byte[] pinnedRootCbor;

    protected PinnedRootHistoryEntity() {}

    public PinnedRootHistoryEntity(Instant appliedAt, byte[] pinnedRootCbor) {
        this.appliedAt = appliedAt;
        this.pinnedRootCbor = pinnedRootCbor;
    }

    public long getId() { return id; }
    public Instant getAppliedAt() { return appliedAt; }
    public byte[] getPinnedRootCbor() { return pinnedRootCbor; }
}
