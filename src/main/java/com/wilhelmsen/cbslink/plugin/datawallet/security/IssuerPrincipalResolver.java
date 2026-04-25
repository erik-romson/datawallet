package com.wilhelmsen.cbslink.plugin.datawallet.security;

import jakarta.servlet.http.HttpServletRequest;

import java.util.Optional;
import java.util.UUID;

public interface IssuerPrincipalResolver {

    Optional<UUID> resolve(HttpServletRequest request);
}
