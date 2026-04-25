package com.wilhelmsen.cbslink.plugin.datawallet.api.verifier;

import com.wilhelmsen.cbslink.plugin.datawallet.audit.AuditService;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.UuidV7;
import com.wilhelmsen.cbslink.plugin.datawallet.domain.VerifierEntity;
import com.wilhelmsen.cbslink.plugin.datawallet.domain.VerifierRepository;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/// Verifier registration and login-blob retrieval.
///
/// Web-origin detection uses the `Origin` request header: if present and matching
/// the configured `datawallet.web-origin`, the web KDF floor applies (64 MiB).
/// Native clients send no `Origin` (or a non-matching one), so the native floor
/// (256 MiB) is enforced.
@RestController
@RequestMapping("/v1/verifiers")
public class VerifierController {

    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();
    private static final Base64.Encoder B64URL_ENC = Base64.getUrlEncoder().withoutPadding();

    private final VerifierRepository verifierRepository;
    private final AuditService auditService;
    private final String webOrigin;

    public VerifierController(VerifierRepository verifierRepository,
                              AuditService auditService,
                              @Value("${datawallet.web-origin:}") String webOrigin) {
        this.verifierRepository = verifierRepository;
        this.auditService = auditService;
        this.webOrigin = webOrigin;
    }

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> register(
            @Valid @RequestBody VerifierRegistrationDto dto,
            @RequestHeader(value = "Origin", required = false) String origin) {

        HandleValidator.validate(dto.handle());

        boolean web = isWebOrigin(origin);
        Argon2idFloor.enforce(dto.kdfParams(), web);

        byte[] encPub = decodeAndCheck(dto.encPublicKey(), 32, "enc_public_key");
        byte[] encKeyId = decodeAndCheck(dto.encKeyId(), 16, "enc_key_id");
        byte[] authPub = decodeAndCheck(dto.authPublicKey(), 32, "auth_public_key");
        byte[] authKeyId = decodeAndCheck(dto.authKeyId(), 16, "auth_key_id");
        byte[] wrappedEnc = B64URL_DEC.decode(dto.wrappedEncPrivateKeyBlob());
        byte[] wrappedAuth = B64URL_DEC.decode(dto.wrappedAuthPrivateKeyBlob());
        byte[] salt = decodeAndCheck(dto.kdfSalt(), 16, "kdf_salt");

        UUID verifierId = UuidV7.now();

        Map<String, Object> kdfMap = new LinkedHashMap<>();
        kdfMap.put("alg", dto.kdfParams().alg());
        kdfMap.put("m", dto.kdfParams().m());
        kdfMap.put("t", dto.kdfParams().t());
        kdfMap.put("p", dto.kdfParams().p());
        kdfMap.put("version", dto.kdfParams().version());

        var entity = new VerifierEntity(
                verifierId, dto.handle(), dto.displayName(),
                encPub, encKeyId, authPub, authKeyId,
                wrappedEnc, wrappedAuth, salt, kdfMap, "active"
        );
        verifierRepository.save(entity);

        auditService.recordEvent(
                AuditService.EventType.VERIFIER_REGISTERED,
                verifierId, null, Collections.emptyMap()
        );

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of("verifier_id", verifierId.toString()));
    }

    @GetMapping(value = "/{handle}/login-blob", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<LoginBlobDto> loginBlob(@PathVariable String handle) {
        VerifierEntity v = verifierRepository.findByHandle(handle)
                .orElseThrow(() -> new HandleNotFound(handle));

        Map<String, Object> kdf = v.getKdfParams();
        var kdfParams = new KdfParams(
                (String) kdf.get("alg"),
                ((Number) kdf.get("m")).longValue(),
                ((Number) kdf.get("t")).intValue(),
                ((Number) kdf.get("p")).intValue(),
                ((Number) kdf.get("version")).intValue()
        );

        var dto = new LoginBlobDto(
                v.getVerifierId(),
                B64URL_ENC.encodeToString(v.getAuthPublicKey()),
                B64URL_ENC.encodeToString(v.getAuthKeyId()),
                B64URL_ENC.encodeToString(v.getEncPublicKey()),
                B64URL_ENC.encodeToString(v.getEncKeyId()),
                B64URL_ENC.encodeToString(v.getWrappedEncPrivateKeyBlob()),
                B64URL_ENC.encodeToString(v.getWrappedAuthPrivateKeyBlob()),
                B64URL_ENC.encodeToString(v.getKdfSalt()),
                kdfParams
        );
        return ResponseEntity.ok(dto);
    }

    private boolean isWebOrigin(String origin) {
        if (origin == null || origin.isBlank() || webOrigin.isBlank()) {
            return false;
        }
        return origin.equals(webOrigin);
    }

    private static byte[] decodeAndCheck(String b64url, int expectedLen, String fieldName) {
        byte[] decoded = B64URL_DEC.decode(b64url);
        if (decoded.length != expectedLen) {
            throw new HandleInvalid(fieldName + " must be " + expectedLen + " bytes, got " + decoded.length);
        }
        return decoded;
    }

    public static class HandleNotFound extends RuntimeException {
        public HandleNotFound(String handle) {
            super("Handle not found: " + handle);
        }
    }
}
