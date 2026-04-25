package com.wilhelmsen.cbslink.plugin.datawallet.observability;

import com.wilhelmsen.cbslink.plugin.datawallet.directory.PinnedRoot;
import com.wilhelmsen.cbslink.plugin.datawallet.directory.PinnedRootHolder;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

import java.time.Clock;

/**
 * Reports DOWN when the pinned root has expired and no in-flight update is available.
 */
@Component("pinnedRootReadiness")
public class PinnedRootReadinessIndicator implements HealthIndicator {

    private final PinnedRootHolder pinnedRootHolder;
    private final Clock clock;

    public PinnedRootReadinessIndicator(PinnedRootHolder pinnedRootHolder, Clock clock) {
        this.pinnedRootHolder = pinnedRootHolder;
        this.clock = clock;
    }

    @Override
    public Health health() {
        PinnedRoot root = pinnedRootHolder.get();
        long nowMs = clock.millis();

        boolean anyValid = root.roots().stream()
                .anyMatch(e -> e.validFrom() <= nowMs && nowMs < e.validUntil());

        if (anyValid) {
            return Health.up().build();
        }

        return Health.down()
                .withDetail("reason", "pinned_root_expired")
                .build();
    }
}
