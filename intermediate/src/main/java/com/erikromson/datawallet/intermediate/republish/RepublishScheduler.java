package com.erikromson.datawallet.intermediate.republish;

import com.erikromson.datawallet.intermediate.cbor.IntermediateCborMapper;
import com.erikromson.datawallet.intermediate.client.DataWalletAdminClient;
import com.erikromson.datawallet.intermediate.denylist.RevocationDenyList;
import com.erikromson.datawallet.intermediate.signer.DirectoryRecordSigner;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Component
public class RepublishScheduler {

    private static final Logger log = LoggerFactory.getLogger(RepublishScheduler.class);
    public static final String REPUBLISH_RESULTS = "republish_results_total";

    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();

    private final DataWalletAdminClient adminClient;
    private final DirectoryRecordSigner recordSigner;
    private final RevocationDenyList denyList;
    private final IntermediateCborMapper cbor;
    private final MeterRegistry meterRegistry;
    private final int batchSize;

    public RepublishScheduler(DataWalletAdminClient adminClient,
                              DirectoryRecordSigner recordSigner,
                              RevocationDenyList denyList,
                              IntermediateCborMapper cbor,
                              MeterRegistry meterRegistry,
                              @Value("${datawallet.intermediate.republish.batch-size:50}") int batchSize) {
        this.adminClient = adminClient;
        this.recordSigner = recordSigner;
        this.denyList = denyList;
        this.cbor = cbor;
        this.meterRegistry = meterRegistry;
        this.batchSize = batchSize;
    }

    @Scheduled(fixedDelayString = "${datawallet.intermediate.republish.interval-ms:302400000}")
    public void republish() {
        try {
            doRepublish();
        } catch (Exception e) {
            meterRegistry.counter(REPUBLISH_RESULTS, "result", "cycle_failed").increment();
            log.warn("Republish cycle failed", e);
        }
    }

    void doRepublish() {
        List<DataWalletAdminClient.ActiveIssuer> issuers = adminClient.getAllActiveIssuers(batchSize);
        log.info("Republish cycle: {} active issuers fetched", issuers.size());

        for (DataWalletAdminClient.ActiveIssuer issuer : issuers) {
            try {
                republishOne(issuer);
            } catch (Exception e) {
                meterRegistry.counter(REPUBLISH_RESULTS, "result", "publish_failed").increment();
                log.warn("Failed to republish issuer {}", issuer.subjectId(), e);
            }
        }
    }

    private void republishOne(DataWalletAdminClient.ActiveIssuer issuer) {
        UUID subjectId = UUID.fromString(issuer.subjectId());
        byte[] keyId = B64URL_DEC.decode(issuer.keyId());

        if (denyList.isRevoked(subjectId, keyId)) {
            meterRegistry.counter(REPUBLISH_RESULTS, "result", "skipped_denylisted").increment();
            log.debug("Skipped denylisted issuer {}", issuer.subjectId());
            return;
        }

        byte[] signedRecord = B64URL_DEC.decode(issuer.signedRecord());
        @SuppressWarnings("unchecked")
        Map<String, Object> recordMap = cbor.readValue(signedRecord, Map.class);

        byte[] publicKey = (byte[]) recordMap.get("public_key");

        byte[] freshRecord = recordSigner.signIssuerRecord(subjectId, publicKey, keyId, "active");
        adminClient.publishDirectoryRecord(freshRecord);
        meterRegistry.counter(REPUBLISH_RESULTS, "result", "republished").increment();
    }
}
