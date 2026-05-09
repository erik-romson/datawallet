package com.erikromson.datawallet.security;

import com.erikromson.datawallet.crypto.Sha256;
import com.erikromson.datawallet.directory.DirectoryRecord;
import com.erikromson.datawallet.directory.DirectoryRecordCodec;
import com.erikromson.datawallet.domain.DirectoryRecordEntity;
import com.erikromson.datawallet.domain.DirectoryRecordRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public class BearerIssuerPrincipalResolver implements IssuerPrincipalResolver {

    private static final Logger log = LoggerFactory.getLogger(BearerIssuerPrincipalResolver.class);
    private static final String BEARER_PREFIX = "Bearer ";
    private static final Base64.Encoder B64URL_NO_PAD = Base64.getUrlEncoder().withoutPadding();

    private final DirectoryRecordRepository directoryRecordRepository;
    private final DirectoryRecordCodec codec;
    private final BearerJwtVerifier jwtVerifier;
    private final String expectedAudience;

    public BearerIssuerPrincipalResolver(DirectoryRecordRepository directoryRecordRepository,
                                          DirectoryRecordCodec codec,
                                          BearerJwtVerifier jwtVerifier,
                                          String expectedAudience) {
        this.directoryRecordRepository = directoryRecordRepository;
        this.codec = codec;
        this.jwtVerifier = jwtVerifier;
        this.expectedAudience = expectedAudience;
    }

    @Override
    public Optional<UUID> resolve(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            return Optional.empty();
        }

        String jwt = authHeader.substring(BEARER_PREFIX.length());

        try {
            byte[] intermediatePublicKey = resolveIntermediatePublicKey();

            BearerClaims claims = jwtVerifier.verify(jwt, expectedAudience, intermediatePublicKey);

            validateInstallRecord(claims);

            return Optional.of(claims.installUuid());
        } catch (BearerRejection e) {
            log.debug("Bearer JWT rejected: {}", e.getMessage());
            return Optional.empty();
        } catch (Exception e) {
            log.debug("Bearer resolution failed: {}", e.getMessage());
            return Optional.empty();
        }
    }

    private byte[] resolveIntermediatePublicKey() {
        List<DirectoryRecordEntity> intermediates = directoryRecordRepository
                .findAll()
                .stream()
                .filter(r -> "intermediate".equals(r.getRecordType()) && "active".equals(r.getStatus()))
                .toList();

        if (intermediates.isEmpty()) {
            throw new BearerRejection("No active intermediate directory record found");
        }

        DirectoryRecordEntity entity = intermediates.getFirst();
        DirectoryRecord record = codec.decode(entity.getSignedRecord());

        long nowMs = System.currentTimeMillis();
        if (nowMs < record.validFrom() || nowMs >= record.validUntil()) {
            throw new BearerRejection("Intermediate record is expired");
        }

        return record.publicKey();
    }

    private void validateInstallRecord(BearerClaims claims) {
        List<DirectoryRecordEntity> installRecords = directoryRecordRepository
                .findActiveBySubjectId(claims.installUuid());

        if (installRecords.isEmpty()) {
            throw new BearerRejection("No active directory record for install " + claims.installUuid());
        }

        DirectoryRecordEntity entity = installRecords.getFirst();
        if (!"active".equals(entity.getStatus())) {
            throw new BearerRejection("Install directory record is not active");
        }

        DirectoryRecord record = codec.decode(entity.getSignedRecord());
        String computedJkt = computeJwkThumbprint(record.publicKey());

        if (!computedJkt.equals(claims.jktB64())) {
            throw new BearerRejection("cnf.jkt mismatch: bearer key thumbprint does not match install pubkey");
        }
    }

    public static String computeJwkThumbprint(byte[] ed25519PublicKey) {
        String xB64 = B64URL_NO_PAD.encodeToString(ed25519PublicKey);
        String jwkJson = "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" + xB64 + "\"}";
        byte[] hash = Sha256.hash(jwkJson.getBytes(StandardCharsets.UTF_8));
        return B64URL_NO_PAD.encodeToString(hash);
    }
}
