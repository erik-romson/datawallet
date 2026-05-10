package com.erikromson.datawallet.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * Production resolver: extracts the admin identity from the X.509 client cert.
 * Accepts requests whose certificate OU matches {@code datawallet.security.admin-ou}.
 * Active only when {@code datawallet.security.admin-mtls=true} (the default).
 */
@Component
@ConditionalOnProperty(name = "datawallet.security.admin-mtls", havingValue = "true", matchIfMissing = true)
public class X509AdminPrincipalResolver implements AdminPrincipalResolver {

    private final String requiredOu;

    public X509AdminPrincipalResolver(
            @Value("${datawallet.security.admin-ou:operators}") String requiredOu) {
        this.requiredOu = requiredOu;
    }

    @Override
    public Optional<String> resolve(HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return Optional.empty();
        }
        String name = auth.getName();
        if (name != null && name.contains("OU=" + requiredOu)) {
            return Optional.of(name);
        }
        return Optional.empty();
    }
}
