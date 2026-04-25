package com.wilhelmsen.cbslink.plugin.datawallet.audit;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public interface AuditService {

    void recordEvent(EventType type, UUID actorId, UUID entryId, Map<String, Object> payload);

    Optional<ChainHead> head();

    enum EventType {
        VERIFIER_REGISTERED,
        VERIFIER_LOGIN,
        VERIFIER_LOGOUT,
        VERIFIER_PASSWORD_CHANGED,
        VERIFIER_KEYS_ROTATED,
        ENTRY_CREATED,
        ENTRY_INGESTED,
        ENTRY_UPDATED,
        ENTRY_ACCESSED,
        DIRECTORY_RECORD_PUBLISHED,
        ISSUER_KEY_ROTATED,
        ROOT_KEY_ROTATED,
        PURGE_RAN
    }

    record ChainHead(long seq, byte[] hash) {}
}
