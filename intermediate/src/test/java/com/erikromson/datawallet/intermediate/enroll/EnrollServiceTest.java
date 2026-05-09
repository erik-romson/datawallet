package com.erikromson.datawallet.intermediate.enroll;

import com.erikromson.datawallet.intermediate.attestation.Attestation;
import com.erikromson.datawallet.intermediate.cbor.IntermediateCborMapper;
import com.erikromson.datawallet.intermediate.client.DataWalletAdminClient;
import com.erikromson.datawallet.intermediate.signer.DirectoryRecordSigner;
import com.erikromson.datawallet.intermediate.signer.SoftSigner;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class EnrollServiceTest {

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
    void acceptsWhenAttestationOk() {
        UUID installUuid = UUID.randomUUID();
        byte[] pubkey = new byte[32];
        AtomicInteger publishCount = new AtomicInteger();

        DataWalletAdminClient mockClient = new StubAdminClient(Optional.empty(), publishCount);

        EnrollService service = new EnrollService(
                new StubOkAttestation(), recordSigner, mockClient, signer, meterRegistry);

        EnrollService.EnrollResult result = service.enroll(installUuid, pubkey, "token");
        assertThat(result.signedRecord()).isNotEmpty();
        assertThat(publishCount.get()).isEqualTo(1);
    }

    @Test
    void rejectsWhenAttestationFails() {
        UUID installUuid = UUID.randomUUID();
        byte[] pubkey = new byte[32];

        DataWalletAdminClient mockClient = new StubAdminClient(Optional.empty(), new AtomicInteger());

        EnrollService service = new EnrollService(
                new RejectingAttestation(), recordSigner, mockClient, signer, meterRegistry);

        assertThatThrownBy(() -> service.enroll(installUuid, pubkey, "token"))
                .isInstanceOf(EnrollService.AttestationFailed.class)
                .hasMessageContaining("attestation_failed");
    }

    @Test
    void retrySameInstallUuidReturnsSameReceipt() {
        UUID installUuid = UUID.randomUUID();
        byte[] pubkey = new byte[32];
        byte[] keyId = DirectoryRecordSigner.computeKeyId(pubkey);
        AtomicInteger publishCount = new AtomicInteger();

        byte[] existingRecord = recordSigner.signIssuerRecord(installUuid, pubkey, keyId, "active");
        DataWalletAdminClient.IssuerRecord existing =
                new DataWalletAdminClient.IssuerRecord(keyId, "active", existingRecord);

        DataWalletAdminClient mockClient = new StubAdminClient(Optional.of(existing), publishCount);

        EnrollService service = new EnrollService(
                new StubOkAttestation(), recordSigner, mockClient, signer, meterRegistry);

        EnrollService.EnrollResult first = service.enroll(installUuid, pubkey, "token");
        EnrollService.EnrollResult second = service.enroll(installUuid, pubkey, "token");

        assertThat(first.signedRecord()).isEqualTo(second.signedRecord());
        assertThat(publishCount.get()).isEqualTo(0);
    }

    @Test
    void publishTimeoutReturns502AndDoesNotCache() {
        UUID installUuid = UUID.randomUUID();
        byte[] pubkey = new byte[32];
        AtomicInteger publishCount = new AtomicInteger();

        DataWalletAdminClient failingClient = new FailingPublishClient(publishCount);

        EnrollService service = new EnrollService(
                new StubOkAttestation(), recordSigner, failingClient, signer, meterRegistry);

        assertThatThrownBy(() -> service.enroll(installUuid, pubkey, "token"))
                .isInstanceOf(EnrollService.PublishFailed.class);

        assertThat(publishCount.get()).isEqualTo(1);
    }

    @Test
    void racedIdempotentHitReturnsExistingRecord() {
        UUID installUuid = UUID.randomUUID();
        byte[] pubkey = new byte[32];
        byte[] keyId = DirectoryRecordSigner.computeKeyId(pubkey);

        byte[] existingRecord = recordSigner.signIssuerRecord(installUuid, pubkey, keyId, "active");
        DataWalletAdminClient.IssuerRecord existing =
                new DataWalletAdminClient.IssuerRecord(keyId, "active", existingRecord);

        DataWalletAdminClient racingClient = new RacingClient(existing);

        EnrollService service = new EnrollService(
                new StubOkAttestation(), recordSigner, racingClient, signer, meterRegistry);

        EnrollService.EnrollResult result = service.enroll(installUuid, pubkey, "token");
        assertThat(result.signedRecord()).isEqualTo(existingRecord);
    }

    private static class StubOkAttestation implements Attestation {
        @Override
        public Result verify(String token, UUID installUuid) {
            return Result.ok();
        }
    }

    private static class RejectingAttestation implements Attestation {
        @Override
        public Result verify(String token, UUID installUuid) {
            return Result.reject("attestation_failed");
        }
    }

    private static class StubAdminClient extends DataWalletAdminClient {
        private final Optional<IssuerRecord> existing;
        private final AtomicInteger publishCount;

        StubAdminClient(Optional<IssuerRecord> existing, AtomicInteger publishCount) {
            super("http://unused", java.net.http.HttpClient.newHttpClient());
            this.existing = existing;
            this.publishCount = publishCount;
        }

        @Override
        public void publishDirectoryRecord(byte[] signedRecordCbor) {
            publishCount.incrementAndGet();
        }

        @Override
        public Optional<IssuerRecord> getIssuerRecord(UUID installUuid) {
            return existing;
        }
    }

    private static class FailingPublishClient extends DataWalletAdminClient {
        private final AtomicInteger publishCount;

        FailingPublishClient(AtomicInteger publishCount) {
            super("http://unused", java.net.http.HttpClient.newHttpClient());
            this.publishCount = publishCount;
        }

        @Override
        public void publishDirectoryRecord(byte[] signedRecordCbor) {
            publishCount.incrementAndGet();
            throw new PublishFailedException("Timeout");
        }

        @Override
        public Optional<IssuerRecord> getIssuerRecord(UUID installUuid) {
            return Optional.empty();
        }
    }

    private static class RacingClient extends DataWalletAdminClient {
        private final IssuerRecord record;
        private boolean firstLookup = true;

        RacingClient(IssuerRecord record) {
            super("http://unused", java.net.http.HttpClient.newHttpClient());
            this.record = record;
        }

        @Override
        public void publishDirectoryRecord(byte[] signedRecordCbor) {
            throw new RecordStaleException("409");
        }

        @Override
        public Optional<IssuerRecord> getIssuerRecord(UUID installUuid) {
            if (firstLookup) {
                firstLookup = false;
                return Optional.empty();
            }
            return Optional.of(record);
        }
    }
}
