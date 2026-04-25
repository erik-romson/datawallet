package com.wilhelmsen.cbslink.plugin.datawallet.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Applies cache-control policies based on route sensitivity.
 * - Sensitive routes (/v1/auth/**, /v1/verifiers/*\/login-blob, /v1/shared*, /v1/entries*): no-store
 * - Directory routes (/v1/directory/**): public, max-age=300
 * Must run before Spring Security (order -100) so headers are set even on 401/403 responses.
 */
@Component
@Order(-200)
public class CacheControlFilter extends OncePerRequestFilter {

    private static final String NO_STORE = "no-store, no-cache, must-revalidate, private";
    private static final String PUBLIC_CACHE = "public, max-age=300";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();

        if (path.startsWith("/v1/directory/")) {
            response.setHeader("Cache-Control", PUBLIC_CACHE);
        } else if (isSensitive(path)) {
            response.setHeader("Cache-Control", NO_STORE);
            response.setHeader("Pragma", "no-cache");
        }

        filterChain.doFilter(request, response);
    }

    private boolean isSensitive(String path) {
        if (path.startsWith("/v1/auth/")) return true;
        if (path.startsWith("/v1/shared")) return true;
        if (path.startsWith("/v1/entries")) return true;
        if (path.matches("/v1/verifiers/[^/]+/login-blob")) return true;
        return false;
    }
}
