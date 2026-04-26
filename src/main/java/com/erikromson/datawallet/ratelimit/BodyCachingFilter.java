package com.erikromson.datawallet.ratelimit;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Reads and caches the request body for {@code /v1/auth/**} routes so that both the
 * rate-limit interceptor and the controller's {@code @RequestBody} binding can consume it.
 * Stores the raw bytes as the {@code ratelimit.body} request attribute (accessible from
 * any downstream request wrapper via delegated {@code getAttribute}).
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class BodyCachingFilter extends OncePerRequestFilter {

    static final String BODY_ATTR = "ratelimit.body";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        if (request.getRequestURI().startsWith("/v1/auth/")) {
            CachedBodyHttpServletRequest cached = new CachedBodyHttpServletRequest(request);
            request.setAttribute(BODY_ATTR, cached.getCachedBody());
            chain.doFilter(cached, response);
        } else {
            chain.doFilter(request, response);
        }
    }
}
