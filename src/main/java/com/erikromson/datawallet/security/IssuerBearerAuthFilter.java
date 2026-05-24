package com.erikromson.datawallet.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;
import java.util.UUID;

public class IssuerBearerAuthFilter extends OncePerRequestFilter {

    static final String ISSUER_ID_ATTR = "auth.issuer_id";

    private final BearerIssuerPrincipalResolver resolver;

    public IssuerBearerAuthFilter(BearerIssuerPrincipalResolver resolver) {
        this.resolver = resolver;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        Optional<UUID> issuerId = resolver.resolve(request);
        if (issuerId.isPresent()) {
            request.setAttribute(ISSUER_ID_ATTR, issuerId.get());
            SecurityContextHolder.getContext().setAuthentication(new IssuerPrincipal(issuerId.get()));
        }
        filterChain.doFilter(request, response);
    }
}
