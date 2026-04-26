package com.erikromson.datawallet.api.admin;

import com.erikromson.datawallet.audit.AuditEntity;
import com.erikromson.datawallet.audit.AuditRepository;
import com.erikromson.datawallet.security.AdminPrincipalResolver;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/v1/admin")
public class AdminAuditController {

    private static final int DEFAULT_LIMIT = 50;
    private static final int MAX_LIMIT = 500;

    private final AdminPrincipalResolver adminPrincipalResolver;
    private final AuditRepository auditRepository;

    public AdminAuditController(AdminPrincipalResolver adminPrincipalResolver,
                                 AuditRepository auditRepository) {
        this.adminPrincipalResolver = adminPrincipalResolver;
        this.auditRepository = auditRepository;
    }

    @GetMapping("/audit")
    public ResponseEntity<AuditPageDto> read(
            @RequestParam(value = "since_seq", defaultValue = "0") long sinceSeq,
            @RequestParam(value = "limit", defaultValue = "50") int limit,
            @RequestParam(value = "head", defaultValue = "false") boolean headOnly,
            HttpServletRequest request) {

        adminPrincipalResolver.resolve(request).orElseThrow(AdminDirectoryController.AdminUnauthorized::new);

        if (headOnly) {
            AuditPageDto.ChainHeadDto head = auditRepository.findTopByOrderBySeqDesc()
                    .map(e -> new AuditPageDto.ChainHeadDto(e.getSeq(), AuditPageDto.encodeHash(e.getHash())))
                    .orElse(null);
            return ResponseEntity.ok(new AuditPageDto(null, head));
        }

        int effectiveLimit = Math.min(Math.max(1, limit), MAX_LIMIT);
        List<AuditEntity> entities = auditRepository.findBySeqGreaterThanOrderBySeqAsc(
                sinceSeq, PageRequest.of(0, effectiveLimit));

        List<AuditPageDto.AuditItemDto> items = entities.stream()
                .map(e -> new AuditPageDto.AuditItemDto(
                        e.getSeq(),
                        e.getTs().toString(),
                        e.getEventType(),
                        e.getActorId() != null ? e.getActorId().toString() : null,
                        e.getEntryId() != null ? e.getEntryId().toString() : null,
                        e.getPayload(),
                        AuditPageDto.encodeHash(e.getHash())
                ))
                .toList();

        return ResponseEntity.ok(new AuditPageDto(items, null));
    }
}
