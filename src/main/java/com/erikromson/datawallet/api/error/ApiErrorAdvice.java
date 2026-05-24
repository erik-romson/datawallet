package com.erikromson.datawallet.api.error;

import com.erikromson.datawallet.api.admin.AdminDirectoryController;
import com.erikromson.datawallet.api.auth.AuthController;
import com.erikromson.datawallet.api.directory.DirectoryQueryController;
import com.erikromson.datawallet.api.entry.EntryController;
import com.erikromson.datawallet.ratelimit.AuthLockoutService;
import com.erikromson.datawallet.api.entry.EntryIngestService;
import com.erikromson.datawallet.api.entry.IssuerKeyController;
import com.erikromson.datawallet.api.shared.Cursor;
import com.erikromson.datawallet.api.shared.SharedController;
import com.erikromson.datawallet.api.verifier.HandleInvalid;
import com.erikromson.datawallet.api.verifier.HandleReserved;
import com.erikromson.datawallet.api.verifier.KdfBelowFloor;
import com.erikromson.datawallet.api.verifier.VerifierController;
import com.erikromson.datawallet.api.verifier.VerifierKeyService;
import com.erikromson.datawallet.api.verifier.VerifierRotationController;
import com.erikromson.datawallet.directory.DirectoryRejection;
import com.erikromson.datawallet.envelope.EnvelopeRejection;
import org.slf4j.MDC;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.Map;

@RestControllerAdvice
public class ApiErrorAdvice {

    @ExceptionHandler(HandleInvalid.class)
    public ResponseEntity<ApiError> handleInvalid(HandleInvalid ex) {
        return respond(HttpStatus.BAD_REQUEST, "handle_invalid", ex.getMessage());
    }

    @ExceptionHandler(HandleReserved.class)
    public ResponseEntity<ApiError> handleReserved(HandleReserved ex) {
        return respond(HttpStatus.CONFLICT, "handle_reserved", ex.getMessage());
    }

    @ExceptionHandler(KdfBelowFloor.class)
    public ResponseEntity<ApiError> kdfBelowFloor(KdfBelowFloor ex) {
        return respond(HttpStatus.UNPROCESSABLE_ENTITY, "kdf_below_floor", ex.getMessage());
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ApiError> dataIntegrity(DataIntegrityViolationException ex) {
        String msg = ex.getMostSpecificCause().getMessage();
        if (msg != null && (msg.contains("verifiers_handle_key") || msg.contains("handle"))) {
            return respond(HttpStatus.CONFLICT, "handle_taken", "Handle is already taken");
        }
        if (msg != null && msg.contains("entries_one_current_per_id")) {
            return respond(HttpStatus.CONFLICT, "version_conflict", "Concurrent update conflict");
        }
        return respond(HttpStatus.CONFLICT, "conflict", "Data integrity violation");
    }

    @ExceptionHandler(VerifierController.HandleNotFound.class)
    public ResponseEntity<ApiError> handleNotFound(VerifierController.HandleNotFound ex) {
        return respond(HttpStatus.NOT_FOUND, "handle_not_found", ex.getMessage());
    }

    @ExceptionHandler(AuthController.VerifierNotFound.class)
    public ResponseEntity<ApiError> authVerifierNotFound(AuthController.VerifierNotFound ex) {
        return respond(HttpStatus.NOT_FOUND, "verifier_not_found", ex.getMessage());
    }

    @ExceptionHandler(AuthController.AuthNonceConsumed.class)
    public ResponseEntity<ApiError> authNonceConsumed(AuthController.AuthNonceConsumed ex) {
        return respond(HttpStatus.UNAUTHORIZED, "auth_nonce_consumed", ex.getMessage());
    }

    @ExceptionHandler(AuthController.AuthNonceExpired.class)
    public ResponseEntity<ApiError> authNonceExpired(AuthController.AuthNonceExpired ex) {
        return respond(HttpStatus.UNAUTHORIZED, "auth_nonce_expired", ex.getMessage());
    }

    @ExceptionHandler(AuthController.AuthInvalidSignature.class)
    public ResponseEntity<ApiError> authInvalidSignature(AuthController.AuthInvalidSignature ex) {
        return respond(HttpStatus.UNAUTHORIZED, "auth_invalid_signature", ex.getMessage());
    }

    @ExceptionHandler(AuthController.AuthNonceInvalid.class)
    public ResponseEntity<ApiError> authNonceInvalid(AuthController.AuthNonceInvalid ex) {
        return respond(HttpStatus.UNAUTHORIZED, "auth_nonce_invalid", ex.getMessage());
    }

    @ExceptionHandler(AuthLockoutService.AuthLocked.class)
    public ResponseEntity<ApiError> authLocked(AuthLockoutService.AuthLocked ex) {
        return ResponseEntity.status(423)
                .header("Retry-After", String.valueOf(ex.getRetryAfterSec()))
                .body(ApiError.of("auth_locked", ex.getMessage(), traceId()));
    }

    @ExceptionHandler(SharedController.SchemaViolation.class)
    public ResponseEntity<ApiError> schemaViolation(SharedController.SchemaViolation ex) {
        return respond(HttpStatus.BAD_REQUEST, "schema_violation", ex.getMessage());
    }

    @ExceptionHandler(VerifierController.SchemaViolation.class)
    public ResponseEntity<ApiError> verifierSchemaViolation(VerifierController.SchemaViolation ex) {
        return respond(HttpStatus.BAD_REQUEST, "schema_violation", ex.getMessage());
    }

    @ExceptionHandler(Cursor.BadCursor.class)
    public ResponseEntity<ApiError> badCursor(Cursor.BadCursor ex) {
        return respond(HttpStatus.BAD_REQUEST, "bad_cursor", ex.getMessage());
    }

    @ExceptionHandler(SharedController.EntryNotFound.class)
    public ResponseEntity<ApiError> entryNotFound(SharedController.EntryNotFound ex) {
        return respond(HttpStatus.NOT_FOUND, "entry_not_found", ex.getMessage());
    }

    @ExceptionHandler(SharedController.EntryPurged.class)
    public ResponseEntity<ApiError> entryPurged(SharedController.EntryPurged ex) {
        return respond(HttpStatus.GONE, "entry_purged", ex.getMessage());
    }

    @ExceptionHandler(EntryController.IssuerUnauthorized.class)
    public ResponseEntity<ApiError> issuerUnauthorized(EntryController.IssuerUnauthorized ex) {
        return respond(HttpStatus.UNAUTHORIZED, "issuer_unauthorized", ex.getMessage());
    }

    @ExceptionHandler(IssuerKeyController.IssuerUnauthorized.class)
    public ResponseEntity<ApiError> issuerKeyUnauthorized(IssuerKeyController.IssuerUnauthorized ex) {
        return respond(HttpStatus.UNAUTHORIZED, "issuer_unauthorized", ex.getMessage());
    }

    @ExceptionHandler(IssuerKeyController.IssuerRotationForbidden.class)
    public ResponseEntity<ApiError> issuerRotationForbidden(IssuerKeyController.IssuerRotationForbidden ex) {
        return respond(HttpStatus.FORBIDDEN, "issuer_rotation_forbidden", ex.getMessage());
    }

    @ExceptionHandler(IssuerKeyController.KeyRotationStale.class)
    public ResponseEntity<ApiError> issuerKeyRotationStale(IssuerKeyController.KeyRotationStale ex) {
        return respond(HttpStatus.UNPROCESSABLE_ENTITY, "key_rotation_stale", ex.getMessage());
    }

    @ExceptionHandler(EntryIngestService.IssuerMismatch.class)
    public ResponseEntity<ApiError> issuerMismatch(EntryIngestService.IssuerMismatch ex) {
        return respond(HttpStatus.FORBIDDEN, "issuer_mismatch", ex.getMessage());
    }

    @ExceptionHandler(EntryIngestService.EntryIdTaken.class)
    public ResponseEntity<ApiError> entryIdTaken(EntryIngestService.EntryIdTaken ex) {
        return respond(HttpStatus.CONFLICT, "entry_id_taken", ex.getMessage());
    }

    @ExceptionHandler(EntryIngestService.EntryNotFound.class)
    public ResponseEntity<ApiError> ingestEntryNotFound(EntryIngestService.EntryNotFound ex) {
        return respond(HttpStatus.NOT_FOUND, "entry_not_found", ex.getMessage());
    }

    @ExceptionHandler(EntryIngestService.RewrapOnlyForbidden.class)
    public ResponseEntity<ApiError> rewrapOnlyForbidden(EntryIngestService.RewrapOnlyForbidden ex) {
        return respond(HttpStatus.CONFLICT, "rewrap_only_forbidden", ex.getMessage());
    }

    @ExceptionHandler(EntryIngestService.VersionConflict.class)
    public ResponseEntity<ApiError> versionConflict(EntryIngestService.VersionConflict ex) {
        return respond(HttpStatus.CONFLICT, "version_conflict", ex.getMessage(),
                Map.of("current_version", ex.getCurrentVersion()));
    }

    @ExceptionHandler(EnvelopeRejection.MalformedCbor.class)
    public ResponseEntity<ApiError> malformedCbor(EnvelopeRejection.MalformedCbor ex) {
        return respond(HttpStatus.UNPROCESSABLE_ENTITY, "malformed_cbor", ex.getMessage());
    }

    @ExceptionHandler(EnvelopeRejection.UnsupportedVersion.class)
    public ResponseEntity<ApiError> unsupportedVersion(EnvelopeRejection.UnsupportedVersion ex) {
        return respond(HttpStatus.UNPROCESSABLE_ENTITY, "version_unsupported", ex.getMessage());
    }

    @ExceptionHandler(EnvelopeRejection.SignatureInvalid.class)
    public ResponseEntity<ApiError> signatureInvalid(EnvelopeRejection.SignatureInvalid ex) {
        return respond(HttpStatus.UNPROCESSABLE_ENTITY, "signature_invalid", ex.getMessage());
    }

    @ExceptionHandler(EnvelopeRejection.IssuerKeyNotActiveAt.class)
    public ResponseEntity<ApiError> issuerKeyNotActiveAt(EnvelopeRejection.IssuerKeyNotActiveAt ex) {
        return respond(HttpStatus.UNPROCESSABLE_ENTITY, "issuer_key_not_active", ex.getMessage());
    }

    @ExceptionHandler(EnvelopeRejection.CiphertextHashMismatch.class)
    public ResponseEntity<ApiError> ciphertextHashMismatch(EnvelopeRejection.CiphertextHashMismatch ex) {
        return respond(HttpStatus.UNPROCESSABLE_ENTITY, "ciphertext_hash_mismatch", ex.getMessage());
    }

    @ExceptionHandler(EnvelopeRejection.class)
    public ResponseEntity<ApiError> envelopeRejection(EnvelopeRejection ex) {
        return respond(HttpStatus.UNPROCESSABLE_ENTITY, "envelope_rejected", ex.getMessage());
    }

    @ExceptionHandler(VerifierRotationController.RotationForbidden.class)
    public ResponseEntity<ApiError> rotationForbidden(VerifierRotationController.RotationForbidden ex) {
        return respond(HttpStatus.FORBIDDEN, "rotation_forbidden", ex.getMessage());
    }

    @ExceptionHandler(VerifierKeyService.KeyRotationStale.class)
    public ResponseEntity<ApiError> keyRotationStale(VerifierKeyService.KeyRotationStale ex) {
        return respond(HttpStatus.UNPROCESSABLE_ENTITY, "key_rotation_stale", ex.getMessage());
    }

    @ExceptionHandler(VerifierKeyService.VerifierNotFound.class)
    public ResponseEntity<ApiError> verifierNotFound(VerifierKeyService.VerifierNotFound ex) {
        return respond(HttpStatus.NOT_FOUND, "verifier_not_found", ex.getMessage());
    }

    @ExceptionHandler(AdminDirectoryController.AdminUnauthorized.class)
    public ResponseEntity<ApiError> adminUnauthorized(AdminDirectoryController.AdminUnauthorized ex) {
        return respond(HttpStatus.UNAUTHORIZED, "admin_required", ex.getMessage());
    }

    @ExceptionHandler(AdminDirectoryController.RecordStale.class)
    public ResponseEntity<ApiError> recordStale(AdminDirectoryController.RecordStale ex) {
        return respond(HttpStatus.CONFLICT, "directory_record_stale", ex.getMessage());
    }

    @ExceptionHandler(DirectoryRejection.MalformedCbor.class)
    public ResponseEntity<ApiError> directoryMalformedCbor(DirectoryRejection.MalformedCbor ex) {
        return respond(HttpStatus.BAD_REQUEST, "malformed_body", ex.getMessage());
    }

    @ExceptionHandler(DirectoryRejection.QuorumBelowThreshold.class)
    public ResponseEntity<ApiError> quorumBelowThreshold(DirectoryRejection.QuorumBelowThreshold ex) {
        return respond(HttpStatus.UNPROCESSABLE_ENTITY, "quorum_below_threshold", ex.getMessage());
    }

    @ExceptionHandler(DirectoryRejection.class)
    public ResponseEntity<ApiError> directoryRejection(DirectoryRejection ex) {
        return respond(HttpStatus.UNPROCESSABLE_ENTITY, "directory_record_rejected", ex.getMessage());
    }

    @ExceptionHandler(DirectoryQueryController.HandleNotFound.class)
    public ResponseEntity<ApiError> directoryHandleNotFound(DirectoryQueryController.HandleNotFound ex) {
        return respond(HttpStatus.NOT_FOUND, "handle_not_found", ex.getMessage());
    }

    @ExceptionHandler(DirectoryQueryController.IssuerNotFound.class)
    public ResponseEntity<ApiError> directoryIssuerNotFound(DirectoryQueryController.IssuerNotFound ex) {
        return respond(HttpStatus.NOT_FOUND, "issuer_not_found", ex.getMessage());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> validationError(MethodArgumentNotValidException ex) {
        Map<String, Object> details = new LinkedHashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(fe ->
                details.put(fe.getField(), fe.getDefaultMessage()));
        return respond(HttpStatus.BAD_REQUEST, "validation_error", "Request validation failed", details);
    }

    private ResponseEntity<ApiError> respond(HttpStatus status, String code, String message) {
        return ResponseEntity.status(status)
                .body(ApiError.of(code, message, traceId()));
    }

    private ResponseEntity<ApiError> respond(HttpStatus status, String code, String message,
                                              Map<String, Object> details) {
        return ResponseEntity.status(status)
                .body(ApiError.of(code, message, details, traceId()));
    }

    private String traceId() {
        return MDC.get(TraceIdFilter.TRACE_ID_KEY);
    }
}
