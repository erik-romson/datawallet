package com.erikromson.datawallet.intermediate.security;

import jakarta.servlet.http.HttpServletRequest;

import java.util.Optional;

public interface TriggerAuthResolver {

    Optional<String> resolve(HttpServletRequest request);
}
