package com.erikromson.datawallet.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.UUID;

public class IssuerPrincipal extends AbstractAuthenticationToken {

    private final UUID issuerId;

    public IssuerPrincipal(UUID issuerId) {
        super(List.of(new SimpleGrantedAuthority("ROLE_ISSUER")));
        this.issuerId = issuerId;
        setAuthenticated(true);
    }

    public UUID getIssuerId() { return issuerId; }

    @Override
    public Object getCredentials() { return null; }

    @Override
    public Object getPrincipal() { return this; }

    @Override
    public String getName() { return issuerId.toString(); }
}
