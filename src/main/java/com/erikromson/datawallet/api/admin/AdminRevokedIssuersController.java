package com.erikromson.datawallet.api.admin;

import com.erikromson.datawallet.domain.DirectoryRecordEntity;
import com.erikromson.datawallet.domain.DirectoryRecordRepository;
import com.erikromson.datawallet.security.AdminPrincipalResolver;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;
import java.util.List;

@RestController
@RequestMapping("/v1/admin")
public class AdminRevokedIssuersController {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    private final AdminPrincipalResolver adminPrincipalResolver;
    private final DirectoryRecordRepository repository;

    public AdminRevokedIssuersController(AdminPrincipalResolver adminPrincipalResolver,
                                          DirectoryRecordRepository repository) {
        this.adminPrincipalResolver = adminPrincipalResolver;
        this.repository = repository;
    }

    @GetMapping("/directory/revoked-issuers")
    public ResponseEntity<List<RevokedIssuerDto>> revokedIssuers(HttpServletRequest request) {
        adminPrincipalResolver.resolve(request).orElseThrow(AdminDirectoryController.AdminUnauthorized::new);

        List<RevokedIssuerDto> dtos = repository.findRevokedIssuers().stream()
                .map(this::toDto)
                .toList();

        return ResponseEntity.ok(dtos);
    }

    private RevokedIssuerDto toDto(DirectoryRecordEntity entity) {
        return new RevokedIssuerDto(
                entity.getSubjectId().toString(),
                B64URL.encodeToString(entity.getKeyId()),
                entity.getValidUntil().toEpochMilli(),
                entity.getRevokedAt() != null ? entity.getRevokedAt().toEpochMilli() : null
        );
    }

    public record RevokedIssuerDto(
            @JsonProperty("install_uuid") String installUuid,
            @JsonProperty("key_id") String keyId,
            @JsonProperty("valid_until") long validUntil,
            @JsonProperty("revoked_at") Long revokedAt
    ) {}
}
