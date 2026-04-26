package com.erikromson.datawallet.security;

import com.erikromson.datawallet.crypto.Sha256;
import com.erikromson.datawallet.domain.SessionEntity;
import com.erikromson.datawallet.domain.SessionRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

public class BearerAuthFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final Base64.Decoder B64URL = Base64.getUrlDecoder();

    private final SessionRepository sessionRepository;

    public BearerAuthFilter(SessionRepository sessionRepository) {
        this.sessionRepository = sessionRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }

        String tokenB64 = authHeader.substring(BEARER_PREFIX.length());
        byte[] tokenBytes;
        try {
            tokenBytes = B64URL.decode(tokenB64);
        } catch (IllegalArgumentException e) {
            filterChain.doFilter(request, response);
            return;
        }

        byte[] tokenId = Sha256.hash(tokenBytes);
        Optional<SessionEntity> session = sessionRepository.findByTokenId(tokenId);

        if (session.isPresent()) {
            SessionEntity s = session.get();
            if (s.getRevokedAt() == null && s.getExpiresAt().isAfter(Instant.now())) {
                var principal = new SessionPrincipal(s.getVerifierId());
                SecurityContextHolder.getContext().setAuthentication(principal);
                request.setAttribute("auth.verifier_id", s.getVerifierId());
            }
        }

        filterChain.doFilter(request, response);
    }
}
