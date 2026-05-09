package com.erikromson.datawallet.intermediate.revoke;

import com.erikromson.datawallet.intermediate.cbor.IntermediateCborMapper;
import com.erikromson.datawallet.intermediate.client.DataWalletAdminClient;
import com.erikromson.datawallet.intermediate.denylist.RevocationDenyList;
import com.erikromson.datawallet.intermediate.observability.MetricsConfig;
import com.erikromson.datawallet.intermediate.signer.DirectoryRecordSigner;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.UUID;

@Service
public class RevokeService {

    private final DataWalletAdminClient adminClient;
    private final DirectoryRecordSigner recordSigner;
    private final RevocationDenyList denyList;
    private final IntermediateCborMapper cbor;
    private final MeterRegistry meterRegistry;

    public RevokeService(DataWalletAdminClient adminClient,
                         DirectoryRecordSigner recordSigner,
                         RevocationDenyList denyList,
                         IntermediateCborMapper cbor,
                         MeterRegistry meterRegistry) {
        this.adminClient = adminClient;
        this.recordSigner = recordSigner;
        this.denyList = denyList;
        this.cbor = cbor;
        this.meterRegistry = meterRegistry;
    }

    public byte[] revoke(UUID installUuid, byte[] keyId) {
        var existingOpt = adminClient.getIssuerRecord(installUuid);
        if (existingOpt.isEmpty() || !"active".equals(existingOpt.get().status())) {
            meterRegistry.counter(MetricsConfig.REVOKE_RESULTS, "result", "not_found").increment();
            throw new InstallNotFound("No active record for install " + installUuid);
        }

        var existing = existingOpt.get();
        @SuppressWarnings("unchecked")
        Map<String, Object> recordMap = cbor.readValue(existing.signedRecord(), Map.class);
        byte[] publicKey = (byte[]) recordMap.get("public_key");
        long validFrom = ((Number) recordMap.get("valid_from")).longValue();
        long validUntil = ((Number) recordMap.get("valid_until")).longValue();

        byte[] revokedRecord = recordSigner.signRevokedRecord(
                installUuid, publicKey, keyId, validFrom, validUntil);

        try {
            adminClient.publishDirectoryRecord(revokedRecord);
        } catch (DataWalletAdminClient.PublishFailedException e) {
            meterRegistry.counter(MetricsConfig.REVOKE_RESULTS, "result", "publish_failed").increment();
            throw new RevokePublishFailed(e.getMessage());
        }

        denyList.insertEagerly(installUuid, keyId);
        meterRegistry.counter(MetricsConfig.REVOKE_RESULTS, "result", "published").increment();
        return revokedRecord;
    }

    public static final class InstallNotFound extends RuntimeException {
        public InstallNotFound(String message) { super(message); }
    }

    public static final class RevokePublishFailed extends RuntimeException {
        public RevokePublishFailed(String message) { super(message); }
    }
}
