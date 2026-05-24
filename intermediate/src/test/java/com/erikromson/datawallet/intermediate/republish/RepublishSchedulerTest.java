package com.erikromson.datawallet.intermediate.republish;

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
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class RepublishSchedulerTest {

    private static final byte[] SEED = HexFormat.of().parseHex(
            "0102030405060708091011121314151617181920212223242526272829303132");
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    private static final Instant ORIGINAL_TIME = Instant.parse("2026-01-10T12:00:00Z");
    private static final Instant REPUBLISH_TIME = Instant.parse("2026-01-14T00:00:00Z");

    private SoftSigner signer;
    private IntermediateCborMapper cbor;
    private SimpleMeterRegistry meterRegistry;

    @BeforeEach
    void setUp() {
        signer = new SoftSigner(SEED);
        cbor = new IntermediateCborMapper();
        meterRegistry = new SimpleMeterRegistry();
    }

    @Test
    void republishesEligibleIssuerWithFreshIssuedAt() {
        Clock originalClock = Clock.fixed(ORIGINAL_TIME, ZoneOffset.UTC);
        DirectoryRecordSigner originalSigner = new DirectoryRecordSigner(signer, cbor, originalClock);

        UUID installUuid = UUID.randomUUID();
        byte[] pubkey = new byte[32];
        pubkey[0] = 0x42;
        byte[] keyId = DirectoryRecordSigner.computeKeyId(pubkey);
        byte[] originalRecord = originalSigner.signIssuerRecord(installUuid, pubkey, keyId, "active");

        DataWalletAdminClient.ActiveIssuer issuer = new DataWalletAdminClient.ActiveIssuer(
                installUuid.toString(),
                B64URL.encodeToString(keyId),
                ORIGINAL_TIME.toEpochMilli(),
                ORIGINAL_TIME.plusMillis(365L * 24 * 3600 * 1000).toEpochMilli(),
                ORIGINAL_TIME.toEpochMilli(),
                B64URL.encodeToString(originalRecord)
        );

        RecordingClient client = new RecordingClient(List.of(issuer));
        TestDenyList denyList = new TestDenyList(false);

        Clock republishClock = Clock.fixed(REPUBLISH_TIME, ZoneOffset.UTC);
        DirectoryRecordSigner republishSigner = new DirectoryRecordSigner(signer, cbor, republishClock);

        RepublishScheduler scheduler = new RepublishScheduler(
                client, republishSigner, denyList, cbor, meterRegistry, 50);

        scheduler.doRepublish();

        assertThat(client.published).hasSize(1);

        @SuppressWarnings("unchecked")
        Map<String, Object> republished = cbor.readValue(client.published.getFirst(), Map.class);
        long newIssuedAt = ((Number) republished.get("issued_at")).longValue();
        assertThat(newIssuedAt).isEqualTo(REPUBLISH_TIME.toEpochMilli());
        assertThat(newIssuedAt).isGreaterThan(ORIGINAL_TIME.toEpochMilli());

        assertThat(republished.get("status")).isEqualTo("active");
        assertThat((byte[]) republished.get("key_id")).isEqualTo(keyId);
        assertThat((byte[]) republished.get("public_key")).isEqualTo(pubkey);
        assertThat(republished.get("parent_signature")).isNotNull();

        assertThat(meterRegistry.counter(RepublishScheduler.REPUBLISH_RESULTS, "result", "republished").count())
                .isEqualTo(1.0);
    }

    @Test
    void skipsIssuerOnDenyList() {
        Clock originalClock = Clock.fixed(ORIGINAL_TIME, ZoneOffset.UTC);
        DirectoryRecordSigner originalSigner = new DirectoryRecordSigner(signer, cbor, originalClock);

        UUID installUuid = UUID.randomUUID();
        byte[] pubkey = new byte[32];
        byte[] keyId = DirectoryRecordSigner.computeKeyId(pubkey);
        byte[] originalRecord = originalSigner.signIssuerRecord(installUuid, pubkey, keyId, "active");

        DataWalletAdminClient.ActiveIssuer issuer = new DataWalletAdminClient.ActiveIssuer(
                installUuid.toString(),
                B64URL.encodeToString(keyId),
                ORIGINAL_TIME.toEpochMilli(),
                ORIGINAL_TIME.plusMillis(365L * 24 * 3600 * 1000).toEpochMilli(),
                ORIGINAL_TIME.toEpochMilli(),
                B64URL.encodeToString(originalRecord)
        );

        RecordingClient client = new RecordingClient(List.of(issuer));
        TestDenyList denyList = new TestDenyList(true);

        Clock republishClock = Clock.fixed(REPUBLISH_TIME, ZoneOffset.UTC);
        DirectoryRecordSigner republishSigner = new DirectoryRecordSigner(signer, cbor, republishClock);

        RepublishScheduler scheduler = new RepublishScheduler(
                client, republishSigner, denyList, cbor, meterRegistry, 50);

        scheduler.doRepublish();

        assertThat(client.published).isEmpty();
        assertThat(meterRegistry.counter(RepublishScheduler.REPUBLISH_RESULTS, "result", "skipped_denylisted").count())
                .isEqualTo(1.0);
    }

    @Test
    void publishFailureDoesNotAbortRemainingIssuers() {
        Clock originalClock = Clock.fixed(ORIGINAL_TIME, ZoneOffset.UTC);
        DirectoryRecordSigner originalSigner = new DirectoryRecordSigner(signer, cbor, originalClock);

        UUID uuid1 = UUID.randomUUID();
        UUID uuid2 = UUID.randomUUID();
        byte[] pubkey1 = new byte[32];
        pubkey1[0] = 0x01;
        byte[] pubkey2 = new byte[32];
        pubkey2[0] = 0x02;
        byte[] keyId1 = DirectoryRecordSigner.computeKeyId(pubkey1);
        byte[] keyId2 = DirectoryRecordSigner.computeKeyId(pubkey2);
        byte[] record1 = originalSigner.signIssuerRecord(uuid1, pubkey1, keyId1, "active");
        byte[] record2 = originalSigner.signIssuerRecord(uuid2, pubkey2, keyId2, "active");

        DataWalletAdminClient.ActiveIssuer issuer1 = new DataWalletAdminClient.ActiveIssuer(
                uuid1.toString(), B64URL.encodeToString(keyId1),
                ORIGINAL_TIME.toEpochMilli(),
                ORIGINAL_TIME.plusMillis(365L * 24 * 3600 * 1000).toEpochMilli(),
                ORIGINAL_TIME.toEpochMilli(),
                B64URL.encodeToString(record1)
        );
        DataWalletAdminClient.ActiveIssuer issuer2 = new DataWalletAdminClient.ActiveIssuer(
                uuid2.toString(), B64URL.encodeToString(keyId2),
                ORIGINAL_TIME.toEpochMilli(),
                ORIGINAL_TIME.plusMillis(365L * 24 * 3600 * 1000).toEpochMilli(),
                ORIGINAL_TIME.toEpochMilli(),
                B64URL.encodeToString(record2)
        );

        FailFirstClient client = new FailFirstClient(List.of(issuer1, issuer2));
        TestDenyList denyList = new TestDenyList(false);

        Clock republishClock = Clock.fixed(REPUBLISH_TIME, ZoneOffset.UTC);
        DirectoryRecordSigner republishSigner = new DirectoryRecordSigner(signer, cbor, republishClock);

        RepublishScheduler scheduler = new RepublishScheduler(
                client, republishSigner, denyList, cbor, meterRegistry, 50);

        scheduler.doRepublish();

        assertThat(client.published).hasSize(1);
        assertThat(meterRegistry.counter(RepublishScheduler.REPUBLISH_RESULTS, "result", "publish_failed").count())
                .isEqualTo(1.0);
        assertThat(meterRegistry.counter(RepublishScheduler.REPUBLISH_RESULTS, "result", "republished").count())
                .isEqualTo(1.0);
    }

    @Test
    void emptyActiveIssuersListCompletesQuietly() {
        RecordingClient client = new RecordingClient(Collections.emptyList());
        TestDenyList denyList = new TestDenyList(false);

        Clock republishClock = Clock.fixed(REPUBLISH_TIME, ZoneOffset.UTC);
        DirectoryRecordSigner republishSigner = new DirectoryRecordSigner(signer, cbor, republishClock);

        RepublishScheduler scheduler = new RepublishScheduler(
                client, republishSigner, denyList, cbor, meterRegistry, 50);

        scheduler.doRepublish();

        assertThat(client.published).isEmpty();
    }

    @Test
    void paginatesThroughMultiplePages() {
        Clock originalClock = Clock.fixed(ORIGINAL_TIME, ZoneOffset.UTC);
        DirectoryRecordSigner originalSigner = new DirectoryRecordSigner(signer, cbor, originalClock);

        List<DataWalletAdminClient.ActiveIssuer> page1 = new ArrayList<>();
        List<DataWalletAdminClient.ActiveIssuer> page2 = new ArrayList<>();

        for (int i = 0; i < 2; i++) {
            UUID uuid = UUID.randomUUID();
            byte[] pubkey = new byte[32];
            pubkey[0] = (byte) (0x10 + i);
            byte[] keyId = DirectoryRecordSigner.computeKeyId(pubkey);
            byte[] record = originalSigner.signIssuerRecord(uuid, pubkey, keyId, "active");
            page1.add(new DataWalletAdminClient.ActiveIssuer(
                    uuid.toString(), B64URL.encodeToString(keyId),
                    ORIGINAL_TIME.toEpochMilli(),
                    ORIGINAL_TIME.plusMillis(365L * 24 * 3600 * 1000).toEpochMilli(),
                    ORIGINAL_TIME.toEpochMilli(),
                    B64URL.encodeToString(record)
            ));
        }
        for (int i = 0; i < 2; i++) {
            UUID uuid = UUID.randomUUID();
            byte[] pubkey = new byte[32];
            pubkey[0] = (byte) (0x20 + i);
            byte[] keyId = DirectoryRecordSigner.computeKeyId(pubkey);
            byte[] record = originalSigner.signIssuerRecord(uuid, pubkey, keyId, "active");
            page2.add(new DataWalletAdminClient.ActiveIssuer(
                    uuid.toString(), B64URL.encodeToString(keyId),
                    ORIGINAL_TIME.toEpochMilli(),
                    ORIGINAL_TIME.plusMillis(365L * 24 * 3600 * 1000).toEpochMilli(),
                    ORIGINAL_TIME.toEpochMilli(),
                    B64URL.encodeToString(record)
            ));
        }

        PaginatingClient client = new PaginatingClient(page1, page2);
        TestDenyList denyList = new TestDenyList(false);

        Clock republishClock = Clock.fixed(REPUBLISH_TIME, ZoneOffset.UTC);
        DirectoryRecordSigner republishSigner = new DirectoryRecordSigner(signer, cbor, republishClock);

        RepublishScheduler scheduler = new RepublishScheduler(
                client, republishSigner, denyList, cbor, meterRegistry, 2);

        scheduler.doRepublish();

        assertThat(client.published).hasSize(4);
        assertThat(meterRegistry.counter(RepublishScheduler.REPUBLISH_RESULTS, "result", "republished").count())
                .isEqualTo(4.0);
    }

    private static class RecordingClient extends DataWalletAdminClient {
        final List<byte[]> published = new ArrayList<>();
        private final List<ActiveIssuer> issuers;

        RecordingClient(List<ActiveIssuer> issuers) {
            super("http://unused", java.net.http.HttpClient.newHttpClient());
            this.issuers = issuers;
        }

        @Override
        public ActiveIssuerPage getActiveIssuers(String cursor, int limit) {
            return new ActiveIssuerPage(issuers, null);
        }

        @Override
        public void publishDirectoryRecord(byte[] signedRecordCbor) {
            published.add(signedRecordCbor);
        }

        @Override
        public List<RevokedIssuer> getRevokedIssuers() { return Collections.emptyList(); }
    }

    private static class FailFirstClient extends DataWalletAdminClient {
        final List<byte[]> published = new ArrayList<>();
        private final List<ActiveIssuer> issuers;
        private int publishAttempts = 0;

        FailFirstClient(List<ActiveIssuer> issuers) {
            super("http://unused", java.net.http.HttpClient.newHttpClient());
            this.issuers = issuers;
        }

        @Override
        public ActiveIssuerPage getActiveIssuers(String cursor, int limit) {
            return new ActiveIssuerPage(issuers, null);
        }

        @Override
        public void publishDirectoryRecord(byte[] signedRecordCbor) {
            publishAttempts++;
            if (publishAttempts == 1) {
                throw new PublishFailedException("Simulated failure");
            }
            published.add(signedRecordCbor);
        }

        @Override
        public List<RevokedIssuer> getRevokedIssuers() { return Collections.emptyList(); }
    }

    private static class PaginatingClient extends DataWalletAdminClient {
        final List<byte[]> published = new ArrayList<>();
        private final List<ActiveIssuer> page1;
        private final List<ActiveIssuer> page2;
        private int pageCallCount = 0;

        PaginatingClient(List<ActiveIssuer> page1, List<ActiveIssuer> page2) {
            super("http://unused", java.net.http.HttpClient.newHttpClient());
            this.page1 = page1;
            this.page2 = page2;
        }

        @Override
        public ActiveIssuerPage getActiveIssuers(String cursor, int limit) {
            pageCallCount++;
            if (pageCallCount == 1) {
                return new ActiveIssuerPage(page1, "next_page_cursor");
            }
            return new ActiveIssuerPage(page2, null);
        }

        @Override
        public void publishDirectoryRecord(byte[] signedRecordCbor) {
            published.add(signedRecordCbor);
        }

        @Override
        public List<RevokedIssuer> getRevokedIssuers() { return Collections.emptyList(); }
    }

    private static class TestDenyList extends RevocationDenyList {
        private final boolean alwaysRevoked;

        TestDenyList(boolean alwaysRevoked) {
            super(null, new SimpleMeterRegistry(), 600);
            this.alwaysRevoked = alwaysRevoked;
        }

        @Override protected void startupRebuild() {}
        @Override public boolean isRevoked(UUID installUuid, byte[] keyId) { return alwaysRevoked; }
        @Override public int size() { return 0; }
        @Override public long ageSeconds() { return 0; }
    }
}
