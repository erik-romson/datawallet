package com.wilhelmsen.cbslink.plugin.datawallet.purge;

import com.wilhelmsen.cbslink.plugin.datawallet.audit.AuditService;
import com.wilhelmsen.cbslink.plugin.datawallet.domain.EntryRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

@Component
@ConditionalOnProperty("datawallet.purge.enabled")
public class SupersededPurgeJob {

    private static final Logger log = LoggerFactory.getLogger(SupersededPurgeJob.class);
    private static final int RETENTION_DAYS = 30;

    private final EntryRepository entryRepository;
    private final AuditService auditService;

    public SupersededPurgeJob(EntryRepository entryRepository, AuditService auditService) {
        this.entryRepository = entryRepository;
        this.auditService = auditService;
    }

    @Scheduled(cron = "0 15 3 * * *")
    @Transactional
    public void run() {
        Instant threshold = Instant.now().minus(RETENTION_DAYS, ChronoUnit.DAYS);
        int deleted = entryRepository.deleteSupersededBefore(threshold);
        log.info("Purge job deleted {} superseded entries older than {} days", deleted, RETENTION_DAYS);
        auditService.recordEvent(AuditService.EventType.PURGE_RAN, null, null,
                Map.of("deleted_entries", deleted));
    }
}
