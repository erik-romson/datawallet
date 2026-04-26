package com.erikromson.datawallet.security;

import jakarta.servlet.http.HttpServletRequest;

import java.util.Optional;

public interface AdminPrincipalResolver {

    /**
     * Resolves the admin identity from the incoming request.
     * Returns {@link Optional#empty()} if no valid admin principal is present.
     */
    Optional<String> resolve(HttpServletRequest request);
}
