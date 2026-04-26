package com.erikromson.datawallet.api.verifier;

import com.erikromson.datawallet.security.SessionPrincipal;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/// Verifier password change and key rotation endpoints.
///
/// Both endpoints require a valid session bearer token. The session principal must
/// match the `{verifier_id}` path parameter; mismatches return 403.
@RestController
@RequestMapping("/v1/verifiers")
public class VerifierRotationController {

    private final VerifierKeyService verifierKeyService;
    private final String webOrigin;

    public VerifierRotationController(VerifierKeyService verifierKeyService,
                                       @Value("${datawallet.web-origin:}") String webOrigin) {
        this.verifierKeyService = verifierKeyService;
        this.webOrigin = webOrigin;
    }

    @PostMapping(value = "/{verifier_id}/password", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Void> changePassword(
            @PathVariable("verifier_id") UUID verifierId,
            @Valid @RequestBody PasswordChangeDto dto,
            @RequestHeader(value = "Origin", required = false) String origin,
            @AuthenticationPrincipal SessionPrincipal principal) {

        if (!principal.getVerifierId().equals(verifierId)) {
            throw new RotationForbidden("Cannot modify another verifier's account");
        }

        verifierKeyService.changePassword(verifierId, dto, isWebOrigin(origin));
        return ResponseEntity.noContent().build();
    }

    @PostMapping(value = "/{verifier_id}/rotate-keys", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Void> rotateKeys(
            @PathVariable("verifier_id") UUID verifierId,
            @Valid @RequestBody KeyRotationDto dto,
            @RequestHeader(value = "Origin", required = false) String origin,
            @AuthenticationPrincipal SessionPrincipal principal) {

        if (!principal.getVerifierId().equals(verifierId)) {
            throw new RotationForbidden("Cannot modify another verifier's account");
        }

        verifierKeyService.rotateKeys(verifierId, dto, isWebOrigin(origin));
        return ResponseEntity.noContent().build();
    }

    private boolean isWebOrigin(String origin) {
        if (origin == null || origin.isBlank() || webOrigin.isBlank()) {
            return false;
        }
        return origin.equals(webOrigin);
    }

    public static class RotationForbidden extends RuntimeException {
        public RotationForbidden(String msg) {
            super(msg);
        }
    }
}
