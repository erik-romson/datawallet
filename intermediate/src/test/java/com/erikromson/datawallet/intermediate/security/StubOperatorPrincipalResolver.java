package com.erikromson.datawallet.intermediate.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
@Primary
@Profile("test")
public class StubOperatorPrincipalResolver implements OperatorPrincipalResolver {

    public static final String HEADER = "X-Test-Operator";
    public static final String HEADER_VALUE = "true";

    @Override
    public Optional<String> resolve(HttpServletRequest request) {
        if (HEADER_VALUE.equalsIgnoreCase(request.getHeader(HEADER))) {
            return Optional.of("test-operator");
        }
        return Optional.empty();
    }
}
