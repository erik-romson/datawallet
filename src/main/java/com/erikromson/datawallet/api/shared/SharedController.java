package com.erikromson.datawallet.api.shared;

import com.erikromson.datawallet.domain.EntryEntity;
import com.erikromson.datawallet.domain.EntryRecipientRepository;
import com.erikromson.datawallet.domain.EntryRepository;
import com.erikromson.datawallet.security.SessionPrincipal;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/v1/shared")
public class SharedController {

    private static final MediaType APPLICATION_CBOR = MediaType.parseMediaType("application/cbor");
    private static final String CACHE_CONTROL_PRIVATE = "no-store, no-cache, must-revalidate, private";
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    private final EntryRepository entryRepository;
    private final EntryRecipientRepository entryRecipientRepository;

    public SharedController(EntryRepository entryRepository,
                            EntryRecipientRepository entryRecipientRepository) {
        this.entryRepository = entryRepository;
        this.entryRecipientRepository = entryRecipientRepository;
    }

    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<SharedListDto> list(
            @AuthenticationPrincipal SessionPrincipal principal,
            @RequestParam(required = false) String since,
            @RequestParam(required = false) String cursor,
            @RequestParam(defaultValue = "50") int limit) {

        if (since != null && cursor != null) {
            throw new SchemaViolation("since and cursor are mutually exclusive");
        }

        int clampedLimit = Math.max(1, Math.min(100, limit));
        UUID verifierId = principal.getVerifierId();
        int fetch = clampedLimit + 1;

        List<EntryEntity> rows;
        if (cursor != null) {
            Cursor c = Cursor.decode(cursor);
            rows = entryRepository.findCurrentForVerifierWithCursor(
                    verifierId, c.createdAt(), c.entryId(), fetch);
        } else if (since != null) {
            Instant sinceInstant;
            try {
                sinceInstant = Instant.parse(since);
            } catch (DateTimeParseException e) {
                throw new SchemaViolation("Invalid since format: " + since);
            }
            rows = entryRepository.findCurrentForVerifierSince(verifierId, sinceInstant, fetch);
        } else {
            rows = entryRepository.findCurrentForVerifier(verifierId, fetch);
        }

        boolean hasMore = rows.size() > clampedLimit;
        List<EntryEntity> page = hasMore ? rows.subList(0, clampedLimit) : rows;

        String nextCursor = null;
        if (hasMore) {
            EntryEntity last = page.get(page.size() - 1);
            nextCursor = Cursor.encode(last.getCreatedAt(), last.getEntryId());
        }

        List<SharedListDto.Item> items = page.stream()
                .map(e -> new SharedListDto.Item(
                        e.getEntryId().toString(),
                        e.getIssuerId().toString(),
                        e.getIssuerLabel(),
                        e.getIssuerSigningKeyId() != null
                                ? B64URL.encodeToString(e.getIssuerSigningKeyId()) : null,
                        e.getCreatedAt().toString(),
                        e.getDescription()
                ))
                .toList();

        return ResponseEntity.ok(new SharedListDto(items, nextCursor));
    }

    @GetMapping(value = "/{entryId}", produces = "application/cbor")
    public ResponseEntity<byte[]> detail(
            @AuthenticationPrincipal SessionPrincipal principal,
            @PathVariable UUID entryId) {

        UUID verifierId = principal.getVerifierId();
        Optional<EntryEntity> entry = entryRepository.findCurrentByEntryIdForVerifier(entryId, verifierId);

        if (entry.isPresent()) {
            return ResponseEntity.ok()
                    .header(HttpHeaders.CACHE_CONTROL, CACHE_CONTROL_PRIVATE)
                    .contentType(APPLICATION_CBOR)
                    .body(entry.get().getSignedEnvelope());
        }

        if (entryRecipientRepository.existsByEntryIdAndVerifierId(entryId, verifierId)) {
            throw new EntryPurged(entryId);
        }
        throw new EntryNotFound(entryId);
    }

    public static class SchemaViolation extends RuntimeException {
        public SchemaViolation(String msg) { super(msg); }
    }

    public static class EntryNotFound extends RuntimeException {
        public EntryNotFound(UUID id) { super("Entry not found: " + id); }
    }

    public static class EntryPurged extends RuntimeException {
        public EntryPurged(UUID id) { super("Entry purged: " + id); }
    }
}
