package com.erikromson.datawallet.intermediate.denylist;

import com.erikromson.datawallet.intermediate.client.DataWalletAdminClient;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RevocationDenyListTest {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    @Test
    void startupRebuildFailsClosed() {
        DataWalletAdminClient failing = new FailingClient();
        RevocationDenyList denyList = new RevocationDenyList(failing, new SimpleMeterRegistry(), 600);

        assertThatThrownBy(denyList::startupRebuild)
                .isInstanceOf(RevocationDenyList.DenyListStartupFailure.class);
    }

    @Test
    void runtimeRefreshFailureIncrementsCounterAndContinuesServing() {
        AtomicInteger callCount = new AtomicInteger();
        DataWalletAdminClient intermittentClient = new IntermittentClient(callCount);

        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        RevocationDenyList denyList = new RevocationDenyList(intermittentClient, registry, 600);
        denyList.startupRebuild();

        callCount.set(1);
        denyList.refresh();

        assertThat(registry.counter("denylist_refresh_failures_total").count()).isEqualTo(1.0);
        assertThat(denyList.size()).isEqualTo(0);
    }

    @Test
    void stalenessExceededThrowsDenyListStale() {
        DataWalletAdminClient okClient = new OkClient();
        RevocationDenyList denyList = new RevocationDenyList(okClient, new SimpleMeterRegistry(), 600);

        UUID uuid = UUID.randomUUID();
        byte[] keyId = new byte[16];

        assertThatThrownBy(() -> denyList.isRevoked(uuid, keyId))
                .isInstanceOf(RevocationDenyList.DenyListStaleException.class);
    }

    @Test
    void eagerInsertImmediatelyRevokes() {
        DataWalletAdminClient okClient = new OkClient();
        RevocationDenyList denyList = new RevocationDenyList(okClient, new SimpleMeterRegistry(), 600);
        denyList.startupRebuild();

        UUID uuid = UUID.randomUUID();
        byte[] keyId = new byte[]{1, 2, 3};

        assertThat(denyList.isRevoked(uuid, keyId)).isFalse();

        denyList.insertEagerly(uuid, keyId);
        assertThat(denyList.isRevoked(uuid, keyId)).isTrue();
    }

    private static class FailingClient extends DataWalletAdminClient {
        FailingClient() { super("http://unused", java.net.http.HttpClient.newHttpClient()); }

        @Override
        public List<RevokedIssuer> getRevokedIssuers() {
            throw new ServerUnavailableException("Connection refused");
        }
    }

    private static class OkClient extends DataWalletAdminClient {
        OkClient() { super("http://unused", java.net.http.HttpClient.newHttpClient()); }

        @Override
        public List<RevokedIssuer> getRevokedIssuers() {
            return Collections.emptyList();
        }
    }

    private static class IntermittentClient extends DataWalletAdminClient {
        private final AtomicInteger callCount;

        IntermittentClient(AtomicInteger callCount) {
            super("http://unused", java.net.http.HttpClient.newHttpClient());
            this.callCount = callCount;
        }

        @Override
        public List<RevokedIssuer> getRevokedIssuers() {
            if (callCount.get() > 0) {
                throw new ServerUnavailableException("Connection refused");
            }
            return Collections.emptyList();
        }
    }
}
