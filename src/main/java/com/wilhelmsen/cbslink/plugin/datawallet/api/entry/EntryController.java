package com.wilhelmsen.cbslink.plugin.datawallet.api.entry;

import com.wilhelmsen.cbslink.plugin.datawallet.security.IssuerPrincipalResolver;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/v1/entries")
public class EntryController {

    private final IssuerPrincipalResolver issuerPrincipalResolver;
    private final EntryIngestService ingestService;

    public EntryController(IssuerPrincipalResolver issuerPrincipalResolver,
                           EntryIngestService ingestService) {
        this.issuerPrincipalResolver = issuerPrincipalResolver;
        this.ingestService = ingestService;
    }

    @PostMapping(consumes = "application/cbor", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> create(HttpServletRequest request) throws IOException {
        UUID issuerId = resolveIssuerOrFail(request);
        byte[] body = request.getInputStream().readAllBytes();
        EntryIngestService.IngestResult result = ingestService.ingestNew(issuerId, body);
        return ResponseEntity.status(201).body(Map.of(
                "entry_id", result.entryId().toString(),
                "version", result.version()
        ));
    }

    @PutMapping(value = "/{entryId}", consumes = "application/cbor", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> update(HttpServletRequest request,
                                                       @PathVariable UUID entryId) throws IOException {
        UUID issuerId = resolveIssuerOrFail(request);
        byte[] body = request.getInputStream().readAllBytes();
        EntryIngestService.IngestResult result = ingestService.ingestUpdate(issuerId, entryId, body);
        return ResponseEntity.ok(Map.of(
                "entry_id", result.entryId().toString(),
                "version", result.version()
        ));
    }

    private UUID resolveIssuerOrFail(HttpServletRequest request) {
        return issuerPrincipalResolver.resolve(request)
                .orElseThrow(IssuerUnauthorized::new);
    }

    public static class IssuerUnauthorized extends RuntimeException {
        public IssuerUnauthorized() { super("Issuer authentication required"); }
    }
}
