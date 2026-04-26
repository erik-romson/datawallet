package com.erikromson.datawallet.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * Test-only resolver that grants admin access when the {@code X-Test-Admin: true} header is present.
 * Active only under the {@code it} profile.
 */
@Component
@Primary
@Profile("it")
public class StubAdminPrincipalResolver implements AdminPrincipalResolver {

    public static final String HEADER = "X-Test-Admin";
    public static final String HEADER_VALUE = "true";

    @Override
    public Optional<String> resolve(HttpServletRequest request) {
        String value = request.getHeader(HEADER);
        if (HEADER_VALUE.equalsIgnoreCase(value)) {
            return Optional.of("test-admin");
        }
        return Optional.empty();
    }
}
