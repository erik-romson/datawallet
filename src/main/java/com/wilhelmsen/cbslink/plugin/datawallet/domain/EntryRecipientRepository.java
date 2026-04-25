package com.wilhelmsen.cbslink.plugin.datawallet.domain;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface EntryRecipientRepository extends JpaRepository<EntryRecipientEntity, EntryRecipientEntity.EntryRecipientId> {

    boolean existsByEntryIdAndVerifierId(UUID entryId, UUID verifierId);
}
