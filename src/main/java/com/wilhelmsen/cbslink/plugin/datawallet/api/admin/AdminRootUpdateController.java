package com.wilhelmsen.cbslink.plugin.datawallet.api.admin;

import com.wilhelmsen.cbslink.plugin.datawallet.audit.AuditService;
import com.wilhelmsen.cbslink.plugin.datawallet.directory.DirectoryRejection;
import com.wilhelmsen.cbslink.plugin.datawallet.directory.PinnedRootHolder;
import com.wilhelmsen.cbslink.plugin.datawallet.directory.RootQuorum;
import com.wilhelmsen.cbslink.plugin.datawallet.directory.RootUpdate;
import com.wilhelmsen.cbslink.plugin.datawallet.directory.RootUpdateCodec;
import com.wilhelmsen.cbslink.plugin.datawallet.domain.PinnedRootHistoryEntity;
import com.wilhelmsen.cbslink.plugin.datawallet.domain.PinnedRootHistoryRepository;
import com.wilhelmsen.cbslink.plugin.datawallet.security.AdminPrincipalResolver;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

@RestController
@RequestMapping("/v1/admin")
public class AdminRootUpdateController {

    private final AdminPrincipalResolver adminPrincipalResolver;
    private final PinnedRootHolder pinnedRootHolder;
    private final PinnedRootHistoryRepository historyRepository;
    private final AuditService auditService;
    private final RootUpdateCodec codec = new RootUpdateCodec();

    public AdminRootUpdateController(AdminPrincipalResolver adminPrincipalResolver,
                                      PinnedRootHolder pinnedRootHolder,
                                      PinnedRootHistoryRepository historyRepository,
                                      AuditService auditService) {
        this.adminPrincipalResolver = adminPrincipalResolver;
        this.pinnedRootHolder = pinnedRootHolder;
        this.historyRepository = historyRepository;
        this.auditService = auditService;
    }

    @PostMapping(value = "/root-update", consumes = "application/cbor")
    @Transactional
    public ResponseEntity<Void> publish(@RequestBody byte[] body, HttpServletRequest request) {
        adminPrincipalResolver.resolve(request).orElseThrow(AdminDirectoryController.AdminUnauthorized::new);

        RootUpdate update = codec.decode(body);

        if (update.version() != 1) {
            throw new DirectoryRejection.UnsupportedVersion(update.version());
        }

        byte[] signedBytes = codec.signedBytesOf(body);
        RootQuorum.verify(signedBytes, update.oldRootSignatures(), update.issuedAt(), pinnedRootHolder.get());

        byte[] newRootCbor = codec.encodePinnedRoot(update.newPinnedRoot());

        historyRepository.save(new PinnedRootHistoryEntity(Instant.now(), newRootCbor));
        pinnedRootHolder.update(update.newPinnedRoot());

        auditService.recordEvent(AuditService.EventType.ROOT_KEY_ROTATED, null, null,
                Map.of("threshold", update.newPinnedRoot().threshold(),
                       "root_count", update.newPinnedRoot().roots().size()));

        return ResponseEntity.status(HttpStatus.CREATED).build();
    }
}
