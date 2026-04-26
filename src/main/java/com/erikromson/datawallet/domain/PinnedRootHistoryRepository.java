package com.erikromson.datawallet.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface PinnedRootHistoryRepository extends JpaRepository<PinnedRootHistoryEntity, Long> {

    Optional<PinnedRootHistoryEntity> findTopByOrderByIdDesc();
}
