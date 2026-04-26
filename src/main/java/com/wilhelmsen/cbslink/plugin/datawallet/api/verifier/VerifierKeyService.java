package com.wilhelmsen.cbslink.plugin.datawallet.api.verifier;

import com.wilhelmsen.cbslink.plugin.datawallet.audit.AuditService;
import com.wilhelmsen.cbslink.plugin.datawallet.domain.DirectoryRecordRepository;
import com.wilhelmsen.cbslink.plugin.datawallet.domain.SessionRepository;
import com.wilhelmsen.cbslink.plugin.datawallet.domain.VerifierEntity;
import com.wilhelmsen.cbslink.plugin.datawallet.domain.VerifierRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

@Service
@Transactional
public class VerifierKeyService {

    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();
    private static final Base64.Encoder B64URL_ENC = Base64.getUrlEncoder().withoutPadding();

    private final VerifierRepository verifierRepository;
    private final SessionRepository sessionRepository;
    private final DirectoryRecordRepository directoryRecordRepository;
    private final AuditService auditService;

    public VerifierKeyService(VerifierRepository verifierRepository,
                               SessionRepository sessionRepository,
                               DirectoryRecordRepository directoryRecordRepository,
                               AuditService auditService) {
        this.verifierRepository = verifierRepository;
        this.sessionRepository = sessionRepository;
        this.directoryRecordRepository = directoryRecordRepository;
        this.auditService = auditService;
    }

    public void changePassword(UUID verifierId, PasswordChangeDto dto, boolean isWebOrigin) {
        Argon2idFloor.enforce(dto.kdfParams(), isWebOrigin);

        VerifierEntity v = verifierRepository.findById(verifierId)
                .orElseThrow(() -> new VerifierNotFound(verifierId));

        byte[] wrappedEnc = B64URL_DEC.decode(dto.wrappedEncPrivateKeyBlob());
        byte[] wrappedAuth = B64URL_DEC.decode(dto.wrappedAuthPrivateKeyBlob());
        byte[] salt = decodeAndCheck(dto.kdfSalt(), 16, "kdf_salt");

        v.updatePasswordBlobs(wrappedEnc, wrappedAuth, salt, toKdfMap(dto.kdfParams()));

        auditService.recordEvent(
                AuditService.EventType.VERIFIER_PASSWORD_CHANGED,
                verifierId, null, Collections.emptyMap()
        );
    }

    public void rotateKeys(UUID verifierId, KeyRotationDto dto, boolean isWebOrigin) {
        Argon2idFloor.enforce(dto.kdfParams(), isWebOrigin);

        VerifierEntity v = verifierRepository.findById(verifierId)
                .orElseThrow(() -> new VerifierNotFound(verifierId));

        byte[] oldEncKeyId = B64URL_DEC.decode(dto.oldEncKeyId());
        byte[] oldAuthKeyId = B64URL_DEC.decode(dto.oldAuthKeyId());

        if (!Arrays.equals(oldEncKeyId, v.getEncKeyId())) {
            throw new KeyRotationStale("old_enc_key_id does not match current enc_key_id");
        }
        if (!Arrays.equals(oldAuthKeyId, v.getAuthKeyId())) {
            throw new KeyRotationStale("old_auth_key_id does not match current auth_key_id");
        }

        byte[] encPub = decodeAndCheck(dto.encPublicKey(), 32, "enc_public_key");
        byte[] encKeyId = decodeAndCheck(dto.encKeyId(), 16, "enc_key_id");
        byte[] authPub = decodeAndCheck(dto.authPublicKey(), 32, "auth_public_key");
        byte[] authKeyId = decodeAndCheck(dto.authKeyId(), 16, "auth_key_id");
        byte[] wrappedEnc = B64URL_DEC.decode(dto.wrappedEncPrivateKeyBlob());
        byte[] wrappedAuth = B64URL_DEC.decode(dto.wrappedAuthPrivateKeyBlob());
        byte[] salt = decodeAndCheck(dto.kdfSalt(), 16, "kdf_salt");

        directoryRecordRepository.markPendingRevocationBySubjectIdAndKeyId(verifierId, oldEncKeyId);
        directoryRecordRepository.markPendingRevocationBySubjectIdAndKeyId(verifierId, oldAuthKeyId);

        v.rotateKeys(encPub, encKeyId, authPub, authKeyId, wrappedEnc, wrappedAuth, salt, toKdfMap(dto.kdfParams()));

        sessionRepository.deleteAllByVerifierIdAndRevokedAtIsNull(verifierId);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("old_enc_key_id", B64URL_ENC.encodeToString(oldEncKeyId));
        payload.put("old_auth_key_id", B64URL_ENC.encodeToString(oldAuthKeyId));
        payload.put("new_enc_key_id", B64URL_ENC.encodeToString(encKeyId));
        payload.put("new_auth_key_id", B64URL_ENC.encodeToString(authKeyId));
        auditService.recordEvent(AuditService.EventType.VERIFIER_KEYS_ROTATED, verifierId, null, payload);
    }

    private static Map<String, Object> toKdfMap(KdfParams params) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("alg", params.alg());
        map.put("m", params.m());
        map.put("t", params.t());
        map.put("p", params.p());
        map.put("version", params.version());
        return map;
    }

    private static byte[] decodeAndCheck(String b64url, int expectedLen, String fieldName) {
        byte[] decoded = B64URL_DEC.decode(b64url);
        if (decoded.length != expectedLen) {
            throw new HandleInvalid(fieldName + " must be " + expectedLen + " bytes, got " + decoded.length);
        }
        return decoded;
    }

    public static class VerifierNotFound extends RuntimeException {
        public VerifierNotFound(UUID verifierId) {
            super("Verifier not found: " + verifierId);
        }
    }

    public static class KeyRotationStale extends RuntimeException {
        public KeyRotationStale(String msg) {
            super(msg);
        }
    }
}
