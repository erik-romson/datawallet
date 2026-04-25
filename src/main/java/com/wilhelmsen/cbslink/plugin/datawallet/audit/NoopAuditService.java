package com.wilhelmsen.cbslink.plugin.datawallet.audit;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
@ConditionalOnMissingBean(value = AuditService.class, ignored = NoopAuditService.class)
public class NoopAuditService implements AuditService {

    @Override
    public void recordEvent(EventType type, UUID actorId, UUID entryId, Map<String, Object> payload) {
    }

    @Override
    public Optional<ChainHead> head() {
        return Optional.empty();
    }
}
