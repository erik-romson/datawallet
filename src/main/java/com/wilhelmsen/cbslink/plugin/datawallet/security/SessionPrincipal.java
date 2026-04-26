package com.wilhelmsen.cbslink.plugin.datawallet.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.UUID;

public class SessionPrincipal extends AbstractAuthenticationToken {

    private final UUID verifierId;

    public SessionPrincipal(UUID verifierId) {
        super(List.of(new SimpleGrantedAuthority("ROLE_VERIFIER")));
        this.verifierId = verifierId;
        setAuthenticated(true);
    }

    public UUID getVerifierId() { return verifierId; }

    @Override
    public Object getCredentials() { return null; }

    @Override
    public Object getPrincipal() { return this; }

    @Override
    public String getName() { return verifierId.toString(); }
}
