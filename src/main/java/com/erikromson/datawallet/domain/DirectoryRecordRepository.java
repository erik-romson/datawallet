package com.erikromson.datawallet.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Repository
public interface DirectoryRecordRepository
        extends JpaRepository<DirectoryRecordEntity, DirectoryRecordEntity.DirectoryRecordId> {

    @Query("SELECT d FROM DirectoryRecordEntity d WHERE d.keyId = :keyId")
    List<DirectoryRecordEntity> findByKeyId(@Param("keyId") byte[] keyId);

    @Query("SELECT d FROM DirectoryRecordEntity d WHERE d.subjectId = :subjectId AND d.keyId = :keyId")
    List<DirectoryRecordEntity> findBySubjectIdAndKeyId(
            @Param("subjectId") UUID subjectId,
            @Param("keyId") byte[] keyId);

    @Query("SELECT d FROM DirectoryRecordEntity d WHERE d.subjectId = :subjectId AND d.status = 'active'")
    List<DirectoryRecordEntity> findActiveBySubjectId(@Param("subjectId") UUID subjectId);

    @Query("SELECT d FROM DirectoryRecordEntity d WHERE d.subjectId = :subjectId AND (d.status = 'active' OR (d.status IN ('superseded', 'revoked') AND d.issuedAt >= :retentionCutoff))")
    List<DirectoryRecordEntity> findActiveOrRecentBySubjectId(@Param("subjectId") UUID subjectId,
                                                               @Param("retentionCutoff") Instant retentionCutoff);

    @Modifying
    @Query("UPDATE DirectoryRecordEntity d SET d.pendingRevocation = true WHERE d.subjectId = :subjectId AND d.keyId = :keyId")
    void markPendingRevocationBySubjectIdAndKeyId(@Param("subjectId") UUID subjectId,
                                                   @Param("keyId") byte[] keyId);
}
