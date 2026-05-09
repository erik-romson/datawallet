package com.erikromson.datawallet.intermediate.enroll;

import com.erikromson.datawallet.intermediate.attestation.Attestation;
import com.erikromson.datawallet.intermediate.client.DataWalletAdminClient;
import com.erikromson.datawallet.intermediate.observability.MetricsConfig;
import com.erikromson.datawallet.intermediate.signer.DirectoryRecordSigner;
import com.erikromson.datawallet.intermediate.signer.Signer;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.UUID;

@Service
public class EnrollService {

    private static final Logger log = LoggerFactory.getLogger(EnrollService.class);

    private final Attestation attestation;
    private final DirectoryRecordSigner recordSigner;
    private final DataWalletAdminClient adminClient;
    private final Signer signer;
    private final MeterRegistry meterRegistry;

    public EnrollService(Attestation attestation,
                         DirectoryRecordSigner recordSigner,
                         DataWalletAdminClient adminClient,
                         Signer signer,
                         MeterRegistry meterRegistry) {
        this.attestation = attestation;
        this.recordSigner = recordSigner;
        this.adminClient = adminClient;
        this.signer = signer;
        this.meterRegistry = meterRegistry;
    }

    public EnrollResult enroll(UUID installUuid, byte[] pubkey, String attestationToken) {
        byte[] keyId = DirectoryRecordSigner.computeKeyId(pubkey);

        Attestation.Result attResult = attestation.verify(attestationToken, installUuid);
        if (!attResult.accepted()) {
            meterRegistry.counter(MetricsConfig.ATTESTATION_RESULTS, "result", "rejected").increment();
            meterRegistry.counter(MetricsConfig.ENROLL_RESULTS, "result", "attestation_rejected").increment();
            throw new AttestationFailed(attResult.rejectionCode());
        }
        meterRegistry.counter(MetricsConfig.ATTESTATION_RESULTS, "result", "ok").increment();

        var existingOpt = adminClient.getIssuerRecord(installUuid);
        if (existingOpt.isPresent()) {
            var existing = existingOpt.get();
            if (Arrays.equals(existing.keyId(), keyId) && "active".equals(existing.status())) {
                meterRegistry.counter(MetricsConfig.ENROLL_RESULTS, "result", "idempotent_hit").increment();
                return new EnrollResult(existing.signedRecord());
            }
        }

        byte[] signedRecord = recordSigner.signIssuerRecord(installUuid, pubkey, keyId, "active");

        try {
            adminClient.publishDirectoryRecord(signedRecord);
        } catch (DataWalletAdminClient.RecordStaleException e) {
            var refetched = adminClient.getIssuerRecord(installUuid);
            if (refetched.isPresent()) {
                meterRegistry.counter(MetricsConfig.ENROLL_RESULTS, "result", "raced_idempotent").increment();
                return new EnrollResult(refetched.get().signedRecord());
            }
            throw new PublishFailed("Raced idempotent but record not found on refetch");
        } catch (DataWalletAdminClient.PublishFailedException e) {
            meterRegistry.counter(MetricsConfig.ENROLL_RESULTS, "result", "publish_failed").increment();
            throw new PublishFailed(e.getMessage());
        }

        meterRegistry.counter(MetricsConfig.ENROLL_RESULTS, "result", "published").increment();
        return new EnrollResult(signedRecord);
    }

    public record EnrollResult(byte[] signedRecord) {}

    public static final class AttestationFailed extends RuntimeException {
        private final String rejectionCode;

        public AttestationFailed(String rejectionCode) {
            super("Attestation failed: " + rejectionCode);
            this.rejectionCode = rejectionCode;
        }

        public String rejectionCode() { return rejectionCode; }
    }

    public static final class PublishFailed extends RuntimeException {
        public PublishFailed(String message) { super(message); }
    }
}
