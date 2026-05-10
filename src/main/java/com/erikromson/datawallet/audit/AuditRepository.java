package com.erikromson.datawallet.audit;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface AuditRepository extends JpaRepository<AuditEntity, Long> {

    Optional<AuditEntity> findTopByOrderBySeqDesc();

    List<AuditEntity> findAllByOrderBySeqAsc();

    List<AuditEntity> findBySeqGreaterThanOrderBySeqAsc(long sinceSeq, Pageable pageable);
}
