package com.wilhelmsen.cbslink.plugin.datawallet.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Extracts the issuer principal from the mTLS client certificate's subjectAltName URI
 * of the form {@code urn:datawallet:issuer:<uuid>}.
 */
@Component
@ConditionalOnProperty(name = "datawallet.security.issuer-mtls", havingValue = "true", matchIfMissing = true)
public class X509IssuerPrincipalResolver implements IssuerPrincipalResolver {

    private static final String CERT_ATTR = "jakarta.servlet.request.X509Certificate";
    private static final String URN_PREFIX = "urn:datawallet:issuer:";

    @Override
    public Optional<UUID> resolve(HttpServletRequest request) {
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute(CERT_ATTR);
        if (certs == null || certs.length == 0) {
            return Optional.empty();
        }
        X509Certificate cert = certs[0];
        try {
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans == null) {
                return Optional.empty();
            }
            for (List<?> san : sans) {
                // SAN type 6 = URI
                if (san.size() >= 2 && Integer.valueOf(6).equals(san.get(0))) {
                    String uri = (String) san.get(1);
                    if (uri != null && uri.startsWith(URN_PREFIX)) {
                        String uuidStr = uri.substring(URN_PREFIX.length());
                        return Optional.of(UUID.fromString(uuidStr));
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return Optional.empty();
    }
}
