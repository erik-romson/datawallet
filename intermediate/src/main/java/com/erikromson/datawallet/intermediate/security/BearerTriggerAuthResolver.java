package com.erikromson.datawallet.intermediate.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class BearerTriggerAuthResolver implements TriggerAuthResolver {

    private final String token;

    public BearerTriggerAuthResolver(
            @Value("${datawallet.intermediate.revoke.trigger-token:}") String token) {
        this.token = token;
    }

    @Override
    public Optional<String> resolve(HttpServletRequest request) {
        if (token == null || token.isBlank()) return Optional.empty();
        String auth = request.getHeader("Authorization");
        if (auth != null && auth.startsWith("Bearer ") && auth.substring(7).equals(token)) {
            return Optional.of("trigger");
        }
        return Optional.empty();
    }
}
