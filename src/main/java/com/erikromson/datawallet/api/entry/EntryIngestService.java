package com.erikromson.datawallet.api.entry;

import com.erikromson.datawallet.audit.AuditService;
import com.erikromson.datawallet.domain.EntryEntity;
import com.erikromson.datawallet.domain.EntryRecipientEntity;
import com.erikromson.datawallet.domain.EntryRecipientRepository;
import com.erikromson.datawallet.domain.EntryRepository;
import com.erikromson.datawallet.envelope.EnvelopeVerifier;
import com.erikromson.datawallet.envelope.RecipientWrapping;
import com.erikromson.datawallet.envelope.SharedEnvelope;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
public class EntryIngestService {

    private final EnvelopeVerifier envelopeVerifier;
    private final EntryRepository entryRepository;
    private final EntryRecipientRepository entryRecipientRepository;
    private final AuditService auditService;

    public EntryIngestService(EnvelopeVerifier envelopeVerifier,
                              EntryRepository entryRepository,
                              EntryRecipientRepository entryRecipientRepository,
                              AuditService auditService) {
        this.envelopeVerifier = envelopeVerifier;
        this.entryRepository = entryRepository;
        this.entryRecipientRepository = entryRecipientRepository;
        this.auditService = auditService;
    }

    @Transactional
    public IngestResult ingestNew(UUID issuerPrincipal, byte[] envelopeBytes) {
        SharedEnvelope envelope = envelopeVerifier.verify(envelopeBytes);

        if (!envelope.issuerId().equals(issuerPrincipal)) {
            throw new IssuerMismatch();
        }

        if (entryRepository.existsByEntryIdAndIssuerId(envelope.entryId(), envelope.issuerId())) {
            throw new EntryIdTaken(envelope.entryId());
        }

        EntryEntity entry = new EntryEntity(
                envelope.entryId(), 1, envelope.issuerId(), true,
                Instant.ofEpochMilli(envelope.createdAt()), null,
                envelopeBytes, envelope.ciphertextHash(),
                envelope.issuerLabel(), envelope.issuerSigningKeyId(), envelope.description()
        );
        entryRepository.save(entry);

        for (RecipientWrapping rw : envelope.recipientWrappings()) {
            entryRecipientRepository.save(
                    new EntryRecipientEntity(envelope.entryId(), 1, rw.verifierId(), rw.verifierKeyId())
            );
        }

        auditService.recordEvent(AuditService.EventType.ENTRY_INGESTED, issuerPrincipal, envelope.entryId(),
                Map.of("version", 1));

        return new IngestResult(envelope.entryId(), 1);
    }

    @Transactional
    public IngestResult ingestUpdate(UUID issuerPrincipal, UUID pathEntryId, byte[] envelopeBytes) {
        SharedEnvelope envelope = envelopeVerifier.verify(envelopeBytes);

        if (!envelope.issuerId().equals(issuerPrincipal)) {
            throw new IssuerMismatch();
        }

        if (!envelope.entryId().equals(pathEntryId)) {
            throw new EntryIdMismatch(pathEntryId, envelope.entryId());
        }

        Optional<EntryEntity> currentOpt = entryRepository.findCurrentByEntryId(pathEntryId);
        if (currentOpt.isEmpty()) {
            if (!entryRepository.existsByEntryId(pathEntryId)) {
                throw new EntryNotFound(pathEntryId);
            }
            // Entry exists but no current version — another concurrent update already happened
            int maxVersion = entryRepository.findMaxVersionByEntryId(pathEntryId).orElse(0);
            throw new VersionConflict(maxVersion);
        }
        EntryEntity current = currentOpt.get();

        if (!current.getIssuerId().equals(issuerPrincipal)) {
            throw new IssuerMismatch();
        }

        if (Arrays.equals(envelope.ciphertextHash(), current.getCiphertextHash())) {
            throw new RewrapOnlyForbidden(pathEntryId);
        }

        int newVersion = current.getVersion() + 1;
        Instant now = Instant.now();

        // Optimistic flip: fails with 0 if a concurrent writer already changed is_current
        int flipped = entryRepository.flipCurrentToSuperseded(pathEntryId, current.getVersion(), now);
        if (flipped == 0) {
            int maxVersion = entryRepository.findMaxVersionByEntryId(pathEntryId).orElse(current.getVersion());
            throw new VersionConflict(maxVersion);
        }

        EntryEntity updated = new EntryEntity(
                pathEntryId, newVersion, envelope.issuerId(), true,
                Instant.ofEpochMilli(envelope.createdAt()), null,
                envelopeBytes, envelope.ciphertextHash(),
                envelope.issuerLabel(), envelope.issuerSigningKeyId(), envelope.description()
        );
        try {
            entryRepository.save(updated);
        } catch (DataIntegrityViolationException e) {
            // Concurrent writer already inserted a new current version
            int maxVersion = entryRepository.findMaxVersionByEntryId(pathEntryId)
                    .orElse(current.getVersion());
            throw new VersionConflict(maxVersion);
        }

        for (RecipientWrapping rw : envelope.recipientWrappings()) {
            entryRecipientRepository.save(
                    new EntryRecipientEntity(pathEntryId, newVersion, rw.verifierId(), rw.verifierKeyId())
            );
        }

        auditService.recordEvent(AuditService.EventType.ENTRY_UPDATED, issuerPrincipal, pathEntryId,
                Map.of("version", newVersion));

        return new IngestResult(pathEntryId, newVersion);
    }

    public record IngestResult(UUID entryId, int version) {}

    public static class IssuerMismatch extends RuntimeException {
        public IssuerMismatch() { super("Envelope issuer_id does not match authenticated issuer"); }
    }

    public static class EntryIdTaken extends RuntimeException {
        public EntryIdTaken(UUID entryId) { super("Entry already exists: " + entryId); }
    }

    public static class EntryIdMismatch extends RuntimeException {
        public EntryIdMismatch(UUID path, UUID envelope) {
            super("Path entry_id " + path + " does not match envelope entry_id " + envelope);
        }
    }

    public static class EntryNotFound extends RuntimeException {
        public EntryNotFound(UUID entryId) { super("Entry not found: " + entryId); }
    }

    public static class RewrapOnlyForbidden extends RuntimeException {
        private final UUID entryId;
        public RewrapOnlyForbidden(UUID entryId) {
            super("Rewrap-only update forbidden for entry: " + entryId);
            this.entryId = entryId;
        }
        public UUID getEntryId() { return entryId; }
    }

    public static class VersionConflict extends RuntimeException {
        private final int currentVersion;
        public VersionConflict(int currentVersion) {
            super("Version conflict; current version is " + currentVersion);
            this.currentVersion = currentVersion;
        }
        public int getCurrentVersion() { return currentVersion; }
    }
}
