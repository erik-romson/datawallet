package com.erikromson.datawallet.intermediate.denylist;

import com.erikromson.datawallet.intermediate.client.DataWalletAdminClient;
import com.erikromson.datawallet.intermediate.observability.MetricsConfig;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

@Component
public class RevocationDenyList {

    private static final Logger log = LoggerFactory.getLogger(RevocationDenyList.class);

    private final DataWalletAdminClient client;
    private final long maxStalenessSeconds;
    private final AtomicReference<Set<DenyEntry>> entries = new AtomicReference<>(Collections.emptySet());
    private final AtomicReference<Instant> lastRefresh = new AtomicReference<>();
    private final Counter refreshFailuresCounter;
    private final MeterRegistry meterRegistry;

    public RevocationDenyList(DataWalletAdminClient client,
                              MeterRegistry meterRegistry,
                              @Value("${datawallet.intermediate.denylist.max-staleness-seconds:600}") long maxStalenessSeconds) {
        this.client = client;
        this.meterRegistry = meterRegistry;
        this.maxStalenessSeconds = maxStalenessSeconds;
        this.refreshFailuresCounter = meterRegistry.counter(MetricsConfig.DENYLIST_REFRESH_FAILURES);
    }

    @PostConstruct
    protected void startupRebuild() {
        try {
            rebuild();
        } catch (Exception e) {
            throw new DenyListStartupFailure("Deny-list rebuild failed at startup", e);
        }
    }

    @Scheduled(fixedDelayString = "${datawallet.intermediate.denylist.refresh-interval-seconds:60}000")
    protected void refresh() {
        try {
            rebuild();
        } catch (Exception e) {
            refreshFailuresCounter.increment();
            log.warn("Deny-list refresh failed; continuing with last good snapshot", e);
        }
    }

    private void rebuild() {
        var revoked = client.getRevokedIssuers();
        Set<DenyEntry> newEntries = new HashSet<>();
        for (var r : revoked) {
            newEntries.add(new DenyEntry(
                    UUID.fromString(r.installUuid()),
                    r.keyId()
            ));
        }
        entries.set(newEntries);
        lastRefresh.set(Instant.now());
    }

    public boolean isRevoked(UUID installUuid, byte[] keyId) {
        requireFresh();
        String keyIdB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(keyId);
        return entries.get().contains(new DenyEntry(installUuid, keyIdB64));
    }

    public void insertEagerly(UUID installUuid, byte[] keyId) {
        String keyIdB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(keyId);
        Set<DenyEntry> current = new HashSet<>(entries.get());
        current.add(new DenyEntry(installUuid, keyIdB64));
        entries.set(current);
    }

    public int size() {
        return entries.get().size();
    }

    public long ageSeconds() {
        Instant last = lastRefresh.get();
        if (last == null) return Long.MAX_VALUE;
        return Instant.now().getEpochSecond() - last.getEpochSecond();
    }

    private void requireFresh() {
        if (ageSeconds() > maxStalenessSeconds) {
            throw new DenyListStaleException("Deny-list staleness exceeds " + maxStalenessSeconds + "s");
        }
    }

    private record DenyEntry(UUID installUuid, String keyIdB64) {}

    public static final class DenyListStartupFailure extends RuntimeException {
        public DenyListStartupFailure(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static final class DenyListStaleException extends RuntimeException {
        public DenyListStaleException(String message) {
            super(message);
        }
    }
}
