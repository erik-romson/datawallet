package com.erikromson.datawallet.intermediate.revoke;

import com.erikromson.datawallet.intermediate.cbor.IntermediateCborMapper;
import com.erikromson.datawallet.intermediate.client.DataWalletAdminClient;
import com.erikromson.datawallet.intermediate.denylist.RevocationDenyList;
import com.erikromson.datawallet.intermediate.signer.DirectoryRecordSigner;
import com.erikromson.datawallet.intermediate.signer.SoftSigner;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RevokeServiceTest {

    private static final byte[] SEED = HexFormat.of().parseHex(
            "0102030405060708091011121314151617181920212223242526272829303132");
    private static final Clock FIXED_CLOCK = Clock.fixed(Instant.parse("2026-01-15T12:00:00Z"), ZoneOffset.UTC);

    private SoftSigner signer;
    private IntermediateCborMapper cbor;
    private DirectoryRecordSigner recordSigner;
    private SimpleMeterRegistry meterRegistry;

    @BeforeEach
    void setUp() {
        signer = new SoftSigner(SEED);
        cbor = new IntermediateCborMapper();
        recordSigner = new DirectoryRecordSigner(signer, cbor, FIXED_CLOCK);
        meterRegistry = new SimpleMeterRegistry();
    }

    @Test
    void revokesActiveInstall() {
        UUID installUuid = UUID.randomUUID();
        byte[] pubkey = new byte[32];
        byte[] keyId = DirectoryRecordSigner.computeKeyId(pubkey);

        byte[] activeRecord = recordSigner.signIssuerRecord(installUuid, pubkey, keyId, "active");
        DataWalletAdminClient.IssuerRecord existing =
                new DataWalletAdminClient.IssuerRecord(keyId, "active", activeRecord);

        AtomicInteger publishCount = new AtomicInteger();
        DataWalletAdminClient client = new StubClient(Optional.of(existing), publishCount);
        TestDenyList denyList = new TestDenyList();

        RevokeService service = new RevokeService(client, recordSigner, denyList, cbor, meterRegistry);

        byte[] result = service.revoke(installUuid, keyId);
        assertThat(result).isNotEmpty();
        assertThat(publishCount.get()).isEqualTo(1);

        @SuppressWarnings("unchecked")
        Map<String, Object> map = cbor.readValue(result, Map.class);
        assertThat(map.get("status")).isEqualTo("revoked");

        assertThat(denyList.insertedCount).isEqualTo(1);
    }

    @Test
    void returns404ForUnknownInstall() {
        UUID installUuid = UUID.randomUUID();
        byte[] keyId = new byte[16];
        AtomicInteger publishCount = new AtomicInteger();
        DataWalletAdminClient client = new StubClient(Optional.empty(), publishCount);
        TestDenyList denyList = new TestDenyList();

        RevokeService service = new RevokeService(client, recordSigner, denyList, cbor, meterRegistry);

        assertThatThrownBy(() -> service.revoke(installUuid, keyId))
                .isInstanceOf(RevokeService.InstallNotFound.class);
        assertThat(publishCount.get()).isEqualTo(0);
    }

    @Test
    void publishFailureDoesNotMarkLocally() {
        UUID installUuid = UUID.randomUUID();
        byte[] pubkey = new byte[32];
        byte[] keyId = DirectoryRecordSigner.computeKeyId(pubkey);

        byte[] activeRecord = recordSigner.signIssuerRecord(installUuid, pubkey, keyId, "active");
        DataWalletAdminClient.IssuerRecord existing =
                new DataWalletAdminClient.IssuerRecord(keyId, "active", activeRecord);

        DataWalletAdminClient failClient = new FailingPublishClient(Optional.of(existing));
        TestDenyList denyList = new TestDenyList();

        RevokeService service = new RevokeService(failClient, recordSigner, denyList, cbor, meterRegistry);

        assertThatThrownBy(() -> service.revoke(installUuid, keyId))
                .isInstanceOf(RevokeService.RevokePublishFailed.class);
        assertThat(denyList.insertedCount).isEqualTo(0);
    }

    private static class StubClient extends DataWalletAdminClient {
        private final Optional<IssuerRecord> existing;
        private final AtomicInteger publishCount;

        StubClient(Optional<IssuerRecord> existing, AtomicInteger publishCount) {
            super("http://unused", java.net.http.HttpClient.newHttpClient());
            this.existing = existing;
            this.publishCount = publishCount;
        }

        @Override
        public void publishDirectoryRecord(byte[] signedRecordCbor) { publishCount.incrementAndGet(); }

        @Override
        public Optional<IssuerRecord> getIssuerRecord(UUID installUuid) { return existing; }
    }

    private static class FailingPublishClient extends DataWalletAdminClient {
        private final Optional<IssuerRecord> existing;

        FailingPublishClient(Optional<IssuerRecord> existing) {
            super("http://unused", java.net.http.HttpClient.newHttpClient());
            this.existing = existing;
        }

        @Override
        public void publishDirectoryRecord(byte[] signedRecordCbor) {
            throw new PublishFailedException("Timeout");
        }

        @Override
        public Optional<IssuerRecord> getIssuerRecord(UUID installUuid) { return existing; }
    }

    private static class TestDenyList extends RevocationDenyList {
        int insertedCount = 0;

        TestDenyList() { super(null, new SimpleMeterRegistry(), 600); }

        @Override protected void startupRebuild() {}
        @Override public boolean isRevoked(UUID installUuid, byte[] keyId) { return false; }
        @Override public void insertEagerly(UUID installUuid, byte[] keyId) { insertedCount++; }
        @Override public int size() { return 0; }
        @Override public long ageSeconds() { return 0; }
    }
}
