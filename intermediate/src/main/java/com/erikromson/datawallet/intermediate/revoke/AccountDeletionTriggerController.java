package com.erikromson.datawallet.intermediate.revoke;

import com.erikromson.datawallet.intermediate.security.TriggerAuthResolver;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;
import java.util.Map;
import java.util.UUID;

@RestController
public class AccountDeletionTriggerController {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();

    private final RevokeService revokeService;
    private final TriggerAuthResolver triggerAuthResolver;

    public AccountDeletionTriggerController(RevokeService revokeService,
                                            TriggerAuthResolver triggerAuthResolver) {
        this.revokeService = revokeService;
        this.triggerAuthResolver = triggerAuthResolver;
    }

    @PostMapping("/revoke/trigger")
    public ResponseEntity<?> trigger(@RequestBody TriggerRequest request, HttpServletRequest httpRequest) {
        if (triggerAuthResolver.resolve(httpRequest).isEmpty()) {
            return ResponseEntity.status(401).body(Map.of("error", "trigger_auth_required"));
        }

        UUID installUuid = UUID.fromString(request.installUuid());
        byte[] keyId = B64URL_DEC.decode(request.keyId());

        try {
            byte[] revokedRecord = revokeService.revoke(installUuid, keyId);
            return ResponseEntity.ok(Map.of(
                    "signed_record", B64URL.encodeToString(revokedRecord)
            ));
        } catch (RevokeService.InstallNotFound e) {
            return ResponseEntity.status(404).body(Map.of("error", "not_found"));
        } catch (RevokeService.RevokePublishFailed e) {
            return ResponseEntity.status(502).body(Map.of(
                    "error", "revoke_publish_failed",
                    "retryable", true
            ));
        }
    }

    public record TriggerRequest(
            @JsonProperty("install_uuid") String installUuid,
            @JsonProperty("key_id") String keyId,
            @JsonProperty("reason_code") String reasonCode
    ) {}
}
