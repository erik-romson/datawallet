package com.wilhelmsen.cbslink.plugin.datawallet.api.entry;

import com.wilhelmsen.cbslink.plugin.datawallet.audit.AuditService;
import com.wilhelmsen.cbslink.plugin.datawallet.domain.DirectoryRecordRepository;
import com.wilhelmsen.cbslink.plugin.datawallet.security.IssuerPrincipalResolver;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;
import java.util.Collections;
import java.util.UUID;

/// Issuer signing-key lifecycle endpoint.
///
/// mTLS-protected in production; the `IssuerPrincipalResolver` extracts the issuer UUID from
/// the client certificate. In the IT profile, a stub reads the `X-Test-Issuer-Id` header.
@RestController
@RequestMapping("/v1/issuers")
public class IssuerKeyController {

    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();
    private static final Base64.Encoder B64URL_ENC = Base64.getUrlEncoder().withoutPadding();

    private final IssuerPrincipalResolver issuerPrincipalResolver;
    private final DirectoryRecordRepository directoryRecordRepository;
    private final AuditService auditService;

    public IssuerKeyController(IssuerPrincipalResolver issuerPrincipalResolver,
                                DirectoryRecordRepository directoryRecordRepository,
                                AuditService auditService) {
        this.issuerPrincipalResolver = issuerPrincipalResolver;
        this.directoryRecordRepository = directoryRecordRepository;
        this.auditService = auditService;
    }

    /// Mark the current signing key as pending revocation.
    ///
    /// The new key is NOT registered here; the operator publishes the signed directory
    /// record for the new key out-of-band (step 16). The new key becomes usable only once
    /// that record is published and the resolver cache refreshes.
    @PostMapping(value = "/{issuer_id}/rotate-signing-key", consumes = MediaType.APPLICATION_JSON_VALUE)
    @Transactional
    public ResponseEntity<Void> rotateSigningKey(
            HttpServletRequest request,
            @PathVariable("issuer_id") UUID issuerId,
            @Valid @RequestBody IssuerSigningKeyRotationDto dto) {

        UUID principal = issuerPrincipalResolver.resolve(request)
                .orElseThrow(IssuerUnauthorized::new);

        if (!principal.equals(issuerId)) {
            throw new IssuerRotationForbidden("Issuer principal does not match path issuer_id");
        }

        byte[] oldKeyId = B64URL_DEC.decode(dto.oldKeyId());

        boolean hasActive = directoryRecordRepository
                .findBySubjectIdAndKeyId(issuerId, oldKeyId)
                .stream()
                .anyMatch(r -> "active".equals(r.getStatus()));

        if (!hasActive) {
            throw new KeyRotationStale("No active directory record found for old_key_id");
        }

        directoryRecordRepository.markPendingRevocationBySubjectIdAndKeyId(issuerId, oldKeyId);

        auditService.recordEvent(
                AuditService.EventType.ISSUER_KEY_ROTATED,
                issuerId, null,
                Collections.singletonMap("old_key_id", B64URL_ENC.encodeToString(oldKeyId))
        );

        return ResponseEntity.noContent().build();
    }

    public static class IssuerUnauthorized extends RuntimeException {
        public IssuerUnauthorized() { super("Issuer authentication required"); }
    }

    public static class IssuerRotationForbidden extends RuntimeException {
        public IssuerRotationForbidden(String msg) { super(msg); }
    }

    public static class KeyRotationStale extends RuntimeException {
        public KeyRotationStale(String msg) { super(msg); }
    }
}
