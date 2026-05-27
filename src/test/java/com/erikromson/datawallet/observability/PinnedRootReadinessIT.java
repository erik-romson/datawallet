package com.erikromson.datawallet.observability;

import com.erikromson.datawallet.api.entry.FixtureIssuerKeyResolver;
import com.erikromson.datawallet.directory.PinnedRoot;
import com.erikromson.datawallet.directory.PinnedRootHolder;
import com.erikromson.datawallet.persistence.PostgresTestcontainer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"test", "it"})
@Import({PostgresTestcontainer.class, FixtureIssuerKeyResolver.class})
class PinnedRootReadinessIT {

    @Autowired private MockMvc mvc;
    @MockitoBean private PinnedRootHolder pinnedRootHolder;

    @Test
    void withValidPinnedRoot_readinessIsUp() throws Exception {
        long now = Instant.now().toEpochMilli();
        when(pinnedRootHolder.get()).thenReturn(rootWithValidity(now - 1000, now + 86400_000L));

        mvc.perform(get("/actuator/health/readiness"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }

    @Test
    void withExpiredPinnedRoot_readinessIsDown() throws Exception {
        long past = Instant.now().minusSeconds(3600).toEpochMilli();
        when(pinnedRootHolder.get()).thenReturn(rootWithValidity(past - 86400_000L, past));

        mvc.perform(get("/actuator/health/readiness"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.status").value("DOWN"))
                .andExpect(jsonPath("$.components.pinnedRootReadiness.details.reason").value("pinned_root_expired"));
    }

    private static PinnedRoot rootWithValidity(long validFrom, long validUntil) {
        PinnedRoot.RootEntry entry = new PinnedRoot.RootEntry(
                new byte[16], new byte[32], validFrom, validUntil);
        return new PinnedRoot(1, "ed25519-quorum-v1", 1, List.of(entry));
    }
}
