package com.erikromson.datawallet.api.directory;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.erikromson.datawallet.directory.PinnedRoot;
import com.erikromson.datawallet.directory.PinnedRootHolder;
import com.erikromson.datawallet.domain.DirectoryRecordEntity;
import com.erikromson.datawallet.domain.DirectoryRecordRepository;
import com.erikromson.datawallet.domain.VerifierEntity;
import com.erikromson.datawallet.domain.VerifierRepository;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/v1/directory")
public class DirectoryQueryController {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    private final VerifierRepository verifierRepository;
    private final DirectoryRecordRepository directoryRecordRepository;
    private final PinnedRootHolder pinnedRootHolder;

    public DirectoryQueryController(VerifierRepository verifierRepository,
                                     DirectoryRecordRepository directoryRecordRepository,
                                     PinnedRootHolder pinnedRootHolder) {
        this.verifierRepository = verifierRepository;
        this.directoryRecordRepository = directoryRecordRepository;
        this.pinnedRootHolder = pinnedRootHolder;
    }

    @GetMapping("/verifiers/{handle}")
    public ResponseEntity<DirectoryEnvelope> getVerifier(@PathVariable String handle) {
        Optional<VerifierEntity> verifierOpt = verifierRepository.findByHandle(handle);
        if (verifierOpt.isEmpty()) {
            throw new HandleNotFound("No verifier found for handle: " + handle);
        }
        UUID verifierId = verifierOpt.get().getVerifierId();

        List<DirectoryRecordEntity> records = directoryRecordRepository.findActiveBySubjectId(verifierId);
        List<DirectoryRecordDto> dtos = records.stream().map(this::toDto).toList();

        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(300, TimeUnit.SECONDS).cachePublic())
                .body(new DirectoryEnvelope(dtos));
    }

    @GetMapping("/issuers/{issuerId}")
    public ResponseEntity<DirectoryEnvelope> getIssuer(@PathVariable UUID issuerId) {
        Instant retentionCutoff = Instant.now().minus(30, ChronoUnit.DAYS);
        List<DirectoryRecordEntity> records =
                directoryRecordRepository.findActiveOrRecentBySubjectId(issuerId, retentionCutoff);

        if (records.isEmpty()) {
            throw new IssuerNotFound("No directory records found for issuer: " + issuerId);
        }

        List<DirectoryRecordDto> dtos = records.stream().map(this::toDto).toList();
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(300, TimeUnit.SECONDS).cachePublic())
                .body(new DirectoryEnvelope(dtos));
    }

    @GetMapping("/root")
    public ResponseEntity<RootResponse> getRoot() {
        PinnedRoot pinned = pinnedRootHolder.get();
        List<RootKeyDto> roots = pinned.roots().stream()
                .map(r -> new RootKeyDto(
                        B64URL.encodeToString(r.rootKeyId()),
                        B64URL.encodeToString(r.publicKey()),
                        Instant.ofEpochMilli(r.validFrom()).toString(),
                        Instant.ofEpochMilli(r.validUntil()).toString(),
                        "active"
                ))
                .toList();
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(300, TimeUnit.SECONDS).cachePublic())
                .body(new RootResponse(roots));
    }

    private DirectoryRecordDto toDto(DirectoryRecordEntity entity) {
        return new DirectoryRecordDto(
                B64URL.encodeToString(entity.getKeyId()),
                entity.getStatus(),
                entity.getValidFrom().toString(),
                entity.getValidUntil().toString(),
                entity.getIssuedAt().toString(),
                B64URL.encodeToString(entity.getSignedRecord())
        );
    }

    public record DirectoryEnvelope(@JsonProperty("records") List<DirectoryRecordDto> records) {}

    public record DirectoryRecordDto(
            @JsonProperty("key_id") String keyId,
            @JsonProperty("status") String status,
            @JsonProperty("valid_from") String validFrom,
            @JsonProperty("valid_until") String validUntil,
            @JsonProperty("issued_at") String issuedAt,
            @JsonProperty("signed_record") String signedRecord
    ) {}

    public record RootResponse(@JsonProperty("roots") List<RootKeyDto> roots) {}

    public record RootKeyDto(
            @JsonProperty("root_key_id") String rootKeyId,
            @JsonProperty("public_key") String publicKey,
            @JsonProperty("valid_from") String validFrom,
            @JsonProperty("valid_until") String validUntil,
            @JsonProperty("status") String status
    ) {}

    public static final class HandleNotFound extends RuntimeException {
        public HandleNotFound(String msg) { super(msg); }
    }

    public static final class IssuerNotFound extends RuntimeException {
        public IssuerNotFound(String msg) { super(msg); }
    }
}
