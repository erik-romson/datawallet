package com.wilhelmsen.cbslink.plugin.datawallet.ratelimit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wilhelmsen.cbslink.plugin.datawallet.api.error.ApiError;
import com.wilhelmsen.cbslink.plugin.datawallet.api.error.TraceIdFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.HandlerMapping;

import java.util.Map;

/**
 * Applies token-bucket rate limiting before each request reaches the controller.
 *
 * <p>Looks up the matched route pattern from Spring MVC's handler mapping attributes,
 * finds the policy entry for that (method, pattern) pair, and calls
 * {@link RateLimitService#consume} with the extracted key. Returns {@code 429} with
 * a {@code Retry-After} header when the bucket is exhausted.
 */
@Component
public class RateLimitInterceptor implements HandlerInterceptor {

    private final RateLimitService rateLimitService;
    private final RateLimitPolicy rateLimitPolicy;
    private final ObjectMapper objectMapper;

    public RateLimitInterceptor(RateLimitService rateLimitService,
                                RateLimitPolicy rateLimitPolicy,
                                ObjectMapper objectMapper) {
        this.rateLimitService = rateLimitService;
        this.rateLimitPolicy = rateLimitPolicy;
        this.objectMapper = objectMapper;
    }

    @Override
    @SuppressWarnings("unchecked")
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response,
                             Object handler) throws Exception {
        String pattern = (String) request.getAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE);
        if (pattern == null) {
            return true;
        }

        var policyOpt = rateLimitPolicy.findPolicy(request.getMethod(), pattern);
        if (policyOpt.isEmpty()) {
            return true;
        }

        RateLimitPolicy.PolicyEntry policy = policyOpt.get();

        Map<String, String> pathVars = (Map<String, String>)
                request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
        if (pathVars == null) {
            pathVars = Map.of();
        }

        String key = policy.keyExtractor().extract(request, pathVars);
        RateLimitService.Decision decision = rateLimitService.consume(key, policy.capacity(), policy.refillPerSec());

        if (decision instanceof RateLimitService.Decision.Denied denied) {
            response.setStatus(429);
            response.setHeader("Retry-After", String.valueOf(denied.retryAfterSec()));
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            ApiError error = ApiError.of("rate_limited", "Too many requests", MDC.get(TraceIdFilter.TRACE_ID_KEY));
            objectMapper.writeValue(response.getWriter(), error);
            return false;
        }

        return true;
    }
}
