package com.erikromson.datawallet.intermediate.observability;

import com.erikromson.datawallet.intermediate.denylist.RevocationDenyList;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import org.springframework.context.annotation.Configuration;

import jakarta.annotation.PostConstruct;
import java.util.List;

@Configuration
public class MetricsConfig {

    public static final String ENROLL_RESULTS = "enroll_results_total";
    public static final String TOKEN_RESULTS = "token_results_total";
    public static final String REVOKE_RESULTS = "revoke_results_total";
    public static final String ATTESTATION_RESULTS = "attestation_results_total";
    public static final String DENYLIST_SIZE = "denylist_size";
    public static final String DENYLIST_AGE = "denylist_age_seconds";
    public static final String DENYLIST_REFRESH_FAILURES = "denylist_refresh_failures_total";

    private final MeterRegistry registry;
    private final RevocationDenyList denyList;

    public MetricsConfig(MeterRegistry registry, RevocationDenyList denyList) {
        this.registry = registry;
        this.denyList = denyList;
    }

    @PostConstruct
    void registerMeters() {
        for (String result : List.of("published", "idempotent_hit", "raced_idempotent",
                "publish_failed", "attestation_rejected")) {
            registry.counter(ENROLL_RESULTS, "result", result);
        }

        for (String result : List.of("minted", "attestation_rejected", "revoked",
                "pop_invalid", "record_invalid")) {
            registry.counter(TOKEN_RESULTS, "result", result);
        }

        for (String result : List.of("published", "publish_failed", "not_found")) {
            registry.counter(REVOKE_RESULTS, "result", result);
        }

        for (String result : List.of("ok", "rejected")) {
            registry.counter(ATTESTATION_RESULTS, "result", result);
        }

        registry.gauge(DENYLIST_SIZE, denyList, RevocationDenyList::size);
        registry.gauge(DENYLIST_AGE, denyList, RevocationDenyList::ageSeconds);
    }
}
