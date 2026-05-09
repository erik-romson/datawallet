package com.erikromson.datawallet.intermediate.enroll;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;
import java.util.Map;
import java.util.UUID;

@RestController
public class EnrollController {

    private static final Base64.Decoder B64URL = Base64.getUrlDecoder();
    private static final Base64.Encoder B64URL_ENC = Base64.getUrlEncoder().withoutPadding();

    private final EnrollService enrollService;

    public EnrollController(EnrollService enrollService) {
        this.enrollService = enrollService;
    }

    @PostMapping("/enroll")
    public ResponseEntity<?> enroll(@RequestBody EnrollRequest request) {
        UUID installUuid = UUID.fromString(request.installUuid());
        byte[] pubkey = B64URL.decode(request.pubkey());

        try {
            EnrollService.EnrollResult result = enrollService.enroll(
                    installUuid, pubkey, request.attestationToken());
            return ResponseEntity.ok(Map.of(
                    "signed_record", B64URL_ENC.encodeToString(result.signedRecord()),
                    "token_url", "/token"
            ));
        } catch (EnrollService.AttestationFailed e) {
            return ResponseEntity.status(403).body(Map.of(
                    "error", "attestation_failed",
                    "rejection_code", e.rejectionCode()
            ));
        } catch (EnrollService.PublishFailed e) {
            return ResponseEntity.status(502).body(Map.of(
                    "error", "publish_failed",
                    "retryable", true
            ));
        }
    }

    public record EnrollRequest(
            @JsonProperty("install_uuid") String installUuid,
            @JsonProperty("pubkey") String pubkey,
            @JsonProperty("attestation_token") String attestationToken
    ) {}
}
