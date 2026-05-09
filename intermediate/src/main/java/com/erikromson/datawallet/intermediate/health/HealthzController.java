package com.erikromson.datawallet.intermediate.health;

import com.erikromson.datawallet.intermediate.denylist.RevocationDenyList;
import com.erikromson.datawallet.intermediate.signer.Signer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
public class HealthzController {

    private final RevocationDenyList denyList;
    private final Signer signer;
    private final long maxStalenessSeconds;

    public HealthzController(RevocationDenyList denyList,
                             Signer signer,
                             @Value("${datawallet.intermediate.denylist.max-staleness-seconds:600}") long maxStalenessSeconds) {
        this.denyList = denyList;
        this.signer = signer;
        this.maxStalenessSeconds = maxStalenessSeconds;
    }

    @GetMapping("/healthz")
    public ResponseEntity<Map<String, Object>> healthz() {
        Map<String, Object> checks = new LinkedHashMap<>();
        boolean healthy = true;

        long age = denyList.ageSeconds();
        boolean denyListFresh = age <= maxStalenessSeconds;
        checks.put("denylist_fresh", denyListFresh);
        checks.put("denylist_age_seconds", age);
        if (!denyListFresh) healthy = false;

        boolean signerReachable;
        try {
            signer.sign(new byte[]{0});
            signerReachable = true;
        } catch (Exception e) {
            signerReachable = false;
        }
        checks.put("signer_reachable", signerReachable);
        if (!signerReachable) healthy = false;

        checks.put("healthy", healthy);

        return healthy
                ? ResponseEntity.ok(checks)
                : ResponseEntity.status(503).body(checks);
    }
}
