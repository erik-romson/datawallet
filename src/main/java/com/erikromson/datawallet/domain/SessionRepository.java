package com.erikromson.datawallet.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;
import java.util.UUID;

public interface SessionRepository extends JpaRepository<SessionEntity, byte[]> {

    @Query("SELECT s FROM SessionEntity s WHERE s.tokenId = :tokenId")
    Optional<SessionEntity> findByTokenId(byte[] tokenId);

    @Modifying
    @Query("DELETE FROM SessionEntity s WHERE s.verifierId = :verifierId AND s.revokedAt IS NULL")
    void deleteAllByVerifierIdAndRevokedAtIsNull(UUID verifierId);
}
