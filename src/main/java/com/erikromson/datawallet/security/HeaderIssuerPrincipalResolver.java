package com.erikromson.datawallet.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.UUID;

/// Dev-only fallback that extracts the issuer principal from an
/// {@code X-Test-Issuer-Id} request header. Active **only** when
/// {@code datawallet.security.issuer-mtls=false}, which the production
/// configuration never sets. Pairs with {@link IssuerSecurityConfig}'s opposite
/// {@code @ConditionalOnProperty} guard so exactly one resolver is wired.
///
/// This exists because the equivalent stub in {@code src/test/} is not packaged
/// into the production JAR — but we still want {@code bin/start.sh --dev} +
/// {@code bin/cli.sh share-with-verifier --dev} to work end-to-end without
/// generating client certificates.
@Component
@ConditionalOnProperty(name = "datawallet.security.issuer-mtls", havingValue = "false")
public class HeaderIssuerPrincipalResolver implements IssuerPrincipalResolver {

    public static final String HEADER = "X-Test-Issuer-Id";

    @Override
    public Optional<UUID> resolve(HttpServletRequest request) {
        String header = request.getHeader(HEADER);
        if (header == null || header.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(UUID.fromString(header));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}
