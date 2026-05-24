package com.erikromson.datawallet.api.admin;

import com.erikromson.datawallet.api.shared.Cursor;
import com.erikromson.datawallet.domain.DirectoryRecordEntity;
import com.erikromson.datawallet.domain.DirectoryRecordRepository;
import com.erikromson.datawallet.security.AdminPrincipalResolver;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;
import java.util.List;

@RestController
@RequestMapping("/v1/admin")
public class AdminActiveIssuersController {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    private final AdminPrincipalResolver adminPrincipalResolver;
    private final DirectoryRecordRepository repository;

    public AdminActiveIssuersController(AdminPrincipalResolver adminPrincipalResolver,
                                        DirectoryRecordRepository repository) {
        this.adminPrincipalResolver = adminPrincipalResolver;
        this.repository = repository;
    }

    @GetMapping("/directory/active-issuers")
    public ResponseEntity<ActiveIssuerPageDto> activeIssuers(
            HttpServletRequest request,
            @RequestParam(required = false) String cursor,
            @RequestParam(defaultValue = "50") int limit) {

        adminPrincipalResolver.resolve(request).orElseThrow(AdminDirectoryController.AdminUnauthorized::new);

        int clampedLimit = Math.max(1, Math.min(100, limit));
        int fetch = clampedLimit + 1;

        List<DirectoryRecordEntity> rows;
        if (cursor != null) {
            Cursor c = Cursor.decode(cursor);
            rows = repository.findActiveIssuersWithCursor(c.createdAt(), c.entryId(), fetch);
        } else {
            rows = repository.findActiveIssuers(fetch);
        }

        boolean hasMore = rows.size() > clampedLimit;
        List<DirectoryRecordEntity> page = hasMore ? rows.subList(0, clampedLimit) : rows;

        String nextCursor = null;
        if (hasMore) {
            DirectoryRecordEntity last = page.get(page.size() - 1);
            nextCursor = Cursor.encode(last.getIssuedAt(), last.getSubjectId());
        }

        List<ActiveIssuerDto> items = page.stream()
                .map(this::toDto)
                .toList();

        return ResponseEntity.ok(new ActiveIssuerPageDto(items, nextCursor));
    }

    private ActiveIssuerDto toDto(DirectoryRecordEntity entity) {
        return new ActiveIssuerDto(
                entity.getSubjectId().toString(),
                B64URL.encodeToString(entity.getKeyId()),
                entity.getValidFrom().toEpochMilli(),
                entity.getValidUntil().toEpochMilli(),
                entity.getIssuedAt().toEpochMilli(),
                B64URL.encodeToString(entity.getSignedRecord())
        );
    }

    public record ActiveIssuerDto(
            @JsonProperty("subject_id") String subjectId,
            @JsonProperty("key_id") String keyId,
            @JsonProperty("valid_from") long validFrom,
            @JsonProperty("valid_until") long validUntil,
            @JsonProperty("issued_at") long issuedAt,
            @JsonProperty("signed_record") String signedRecord
    ) {}

    public record ActiveIssuerPageDto(
            List<ActiveIssuerDto> items,
            @JsonProperty("next_cursor") String nextCursor
    ) {}
}
