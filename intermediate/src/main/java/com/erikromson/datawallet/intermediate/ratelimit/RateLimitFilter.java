package com.erikromson.datawallet.intermediate.ratelimit;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Applies per-IP token-bucket rate limits to {@code POST /enroll} and {@code POST /token}.
 *
 * <p>Limits are configurable via:
 * <pre>
 * datawallet.intermediate.ratelimit.enroll.per-ip-capacity        (default 5)
 * datawallet.intermediate.ratelimit.enroll.per-ip-refill-per-minute (default 10)
 * datawallet.intermediate.ratelimit.token.per-ip-capacity         (default 20)
 * datawallet.intermediate.ratelimit.token.per-ip-refill-per-minute  (default 60)
 * </pre>
 *
 * <p>Per-install enrollment quota (1 lifetime enroll per install_uuid) is enforced
 * by {@code EnrollService} idempotency — not by this filter.
 */
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private final InMemoryRateLimiter rateLimiter;
    private final double enrollCapacity;
    private final double enrollRefillPerSec;
    private final double tokenCapacity;
    private final double tokenRefillPerSec;

    public RateLimitFilter(
            InMemoryRateLimiter rateLimiter,
            @Value("${datawallet.intermediate.ratelimit.enroll.per-ip-capacity:5}") double enrollCapacity,
            @Value("${datawallet.intermediate.ratelimit.enroll.per-ip-refill-per-minute:10}") double enrollRefillPerMinute,
            @Value("${datawallet.intermediate.ratelimit.token.per-ip-capacity:20}") double tokenCapacity,
            @Value("${datawallet.intermediate.ratelimit.token.per-ip-refill-per-minute:60}") double tokenRefillPerMinute) {
        this.rateLimiter = rateLimiter;
        this.enrollCapacity = enrollCapacity;
        this.enrollRefillPerSec = enrollRefillPerMinute / 60.0;
        this.tokenCapacity = tokenCapacity;
        this.tokenRefillPerSec = tokenRefillPerMinute / 60.0;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        if ("POST".equalsIgnoreCase(request.getMethod())) {
            String path = request.getServletPath();
            String ip = extractIp(request);
            boolean allowed = switch (path) {
                case "/enroll" -> rateLimiter.tryConsume("enroll:" + ip, enrollCapacity, enrollRefillPerSec);
                case "/token"  -> rateLimiter.tryConsume("token:" + ip, tokenCapacity, tokenRefillPerSec);
                default -> true;
            };
            if (!allowed) {
                response.setStatus(429);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.getWriter().write("{\"error\":\"rate_limited\"}");
                return;
            }
        }
        chain.doFilter(request, response);
    }

    private static String extractIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].strip();
        }
        return request.getRemoteAddr();
    }
}
