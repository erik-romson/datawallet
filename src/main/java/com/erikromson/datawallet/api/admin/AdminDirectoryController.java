package com.erikromson.datawallet.api.admin;

import com.erikromson.datawallet.audit.AuditService;
import com.erikromson.datawallet.directory.DirectoryRecord;
import com.erikromson.datawallet.directory.DirectoryRecordCodec;
import com.erikromson.datawallet.directory.DirectoryRecordVerifier;
import com.erikromson.datawallet.directory.PinnedRootHolder;
import com.erikromson.datawallet.domain.DirectoryRecordEntity;
import com.erikromson.datawallet.domain.DirectoryRecordRepository;
import com.erikromson.datawallet.security.AdminPrincipalResolver;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/v1/admin")
public class AdminDirectoryController {

    private final AdminPrincipalResolver adminPrincipalResolver;
    private final DirectoryRecordVerifier verifier;
    private final DirectoryRecordCodec codec;
    private final PinnedRootHolder pinnedRootHolder;
    private final DirectoryRecordRepository repository;
    private final AuditService auditService;

    public AdminDirectoryController(AdminPrincipalResolver adminPrincipalResolver,
                                     DirectoryRecordVerifier verifier,
                                     DirectoryRecordCodec codec,
                                     PinnedRootHolder pinnedRootHolder,
                                     DirectoryRecordRepository repository,
                                     AuditService auditService) {
        this.adminPrincipalResolver = adminPrincipalResolver;
        this.verifier = verifier;
        this.codec = codec;
        this.pinnedRootHolder = pinnedRootHolder;
        this.repository = repository;
        this.auditService = auditService;
    }

    @PostMapping(value = "/directory", consumes = "application/cbor")
    @Transactional
    public ResponseEntity<Map<String, String>> publish(@RequestBody byte[] body, HttpServletRequest request) {
        adminPrincipalResolver.resolve(request).orElseThrow(AdminUnauthorized::new);

        DirectoryRecord record = verifier.verify(body, pinnedRootHolder.get());

        UUID subjectId = bytesToUuid(record.subjectId());
        DirectoryRecordEntity.DirectoryRecordId pk =
                new DirectoryRecordEntity.DirectoryRecordId(record.recordType(), subjectId, record.keyId());

        Optional<DirectoryRecordEntity> existing = repository.findById(pk);

        if (existing.isPresent()) {
            DirectoryRecordEntity current = existing.get();
            if (current.getIssuedAt().toEpochMilli() >= record.issuedAt()) {
                throw new RecordStale("A fresher record already exists for this key");
            }
            current.setStatus(record.status());
            current.setValidFrom(Instant.ofEpochMilli(record.validFrom()));
            current.setValidUntil(Instant.ofEpochMilli(record.validUntil()));
            current.setIssuedAt(Instant.ofEpochMilli(record.issuedAt()));
            current.setRootKeyId(record.rootSignatures().getFirst().rootKeyId());
            current.setSignedRecord(body);
            if ("revoked".equals(record.status()) && current.isPendingRevocation()) {
                current.setPendingRevocation(false);
            }
        } else {
            DirectoryRecordEntity entity = new DirectoryRecordEntity(
                    record.recordType(), subjectId, record.keyId(),
                    record.status(),
                    Instant.ofEpochMilli(record.validFrom()),
                    Instant.ofEpochMilli(record.validUntil()),
                    Instant.ofEpochMilli(record.issuedAt()),
                    record.rootSignatures().getFirst().rootKeyId(),
                    body
            );
            repository.save(entity);
        }

        auditService.recordEvent(AuditService.EventType.DIRECTORY_RECORD_PUBLISHED, null, null,
                Map.of("record_type", record.recordType(),
                       "subject_id", subjectId.toString(),
                       "status", record.status()));

        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    private static UUID bytesToUuid(byte[] bytes) {
        ByteBuffer buf = ByteBuffer.wrap(bytes);
        return new UUID(buf.getLong(), buf.getLong());
    }

    public static final class AdminUnauthorized extends RuntimeException {
        public AdminUnauthorized() { super("Admin authentication required"); }
    }

    public static final class RecordStale extends RuntimeException {
        public RecordStale(String msg) { super(msg); }
    }
}
