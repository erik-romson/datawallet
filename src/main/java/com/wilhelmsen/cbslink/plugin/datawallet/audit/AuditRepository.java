package com.wilhelmsen.cbslink.plugin.datawallet.audit;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface AuditRepository extends JpaRepository<AuditEntity, Long> {

    /// Locks the latest row for update so concurrent writers serialize on chain insert.
    @Query(value = "SELECT * FROM audit_log ORDER BY seq DESC LIMIT 1 FOR UPDATE", nativeQuery = true)
    Optional<AuditEntity> findHeadForUpdate();

    Optional<AuditEntity> findTopByOrderBySeqDesc();

    List<AuditEntity> findAllByOrderBySeqAsc();

    List<AuditEntity> findBySeqGreaterThanOrderBySeqAsc(long sinceSeq, Pageable pageable);
}
