package com.erikromson.datawallet.ratelimit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.erikromson.datawallet.security.IssuerPrincipalResolver;
import com.erikromson.datawallet.security.SessionPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Registry of per-route rate-limit policies per {@code api.md §6}.
 *
 * <p>Each {@link PolicyEntry} declares the HTTP method, Spring MVC route pattern,
 * a key extractor, burst capacity, and sustained refill rate (tokens/sec).
 */
@Component
public class RateLimitPolicy {

    @FunctionalInterface
    public interface KeyExtractor {
        String extract(HttpServletRequest request, Map<String, String> pathVars);
    }

    public record PolicyEntry(
            String httpMethod,
            String pattern,
            KeyExtractor keyExtractor,
            double capacity,
            double refillPerSec
    ) {}

    private final List<PolicyEntry> entries;
    private final IssuerPrincipalResolver issuerPrincipalResolver;
    private final ObjectMapper objectMapper;

    public RateLimitPolicy(IssuerPrincipalResolver issuerPrincipalResolver, ObjectMapper objectMapper) {
        this.issuerPrincipalResolver = issuerPrincipalResolver;
        this.objectMapper = objectMapper;
        this.entries = buildEntries();
    }

    public Optional<PolicyEntry> findPolicy(String httpMethod, String pattern) {
        for (PolicyEntry entry : entries) {
            if (entry.httpMethod().equalsIgnoreCase(httpMethod) && entry.pattern().equals(pattern)) {
                return Optional.of(entry);
            }
        }
        return Optional.empty();
    }

    private List<PolicyEntry> buildEntries() {
        return List.of(
                new PolicyEntry("POST", "/v1/auth/challenge",
                        (req, vars) -> ip(req) + ":" + bodyVerifierId(req),
                        5, 30.0 / 60),
                new PolicyEntry("POST", "/v1/auth/verify",
                        (req, vars) -> ip(req) + ":" + bodyVerifierId(req),
                        5, 30.0 / 60),
                new PolicyEntry("GET", "/v1/verifiers/{handle}/login-blob",
                        (req, vars) -> ip(req) + ":" + vars.getOrDefault("handle", ""),
                        5, 60.0 / 60),
                new PolicyEntry("GET", "/v1/directory/verifiers/{handle}",
                        (req, vars) -> ip(req),
                        20, 600.0 / 60),
                new PolicyEntry("GET", "/v1/shared",
                        (req, vars) -> verifierId(req),
                        20, 300.0 / 60),
                new PolicyEntry("GET", "/v1/shared/{entryId}",
                        (req, vars) -> verifierId(req),
                        20, 300.0 / 60),
                new PolicyEntry("POST", "/v1/entries",
                        (req, vars) -> issuerId(req),
                        10, 300.0 / 60),
                new PolicyEntry("PUT", "/v1/entries/{entryId}",
                        (req, vars) -> issuerId(req),
                        10, 300.0 / 60)
        );
    }

    private String ip(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].strip();
        }
        return request.getRemoteAddr();
    }

    private String bodyVerifierId(HttpServletRequest request) {
        byte[] body = (byte[]) request.getAttribute(BodyCachingFilter.BODY_ATTR);
        if (body == null || body.length == 0) {
            return "unknown";
        }
        try {
            JsonNode node = objectMapper.readTree(body);
            JsonNode vid = node.get("verifier_id");
            if (vid != null && !vid.isNull()) {
                return vid.asText();
            }
        } catch (Exception ignored) {}
        return "unknown";
    }

    private String verifierId(HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof SessionPrincipal sp) {
            return sp.getVerifierId().toString();
        }
        return ip(request);
    }

    private String issuerId(HttpServletRequest request) {
        return issuerPrincipalResolver.resolve(request)
                .map(Object::toString)
                .orElseGet(() -> ip(request));
    }
}
