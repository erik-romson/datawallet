package com.erikromson.datawallet.intermediate.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.cert.X509Certificate;
import java.util.Optional;

@Component
public class X509OperatorPrincipalResolver implements OperatorPrincipalResolver {

    private static final String CERT_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";

    private final String requiredOu;

    public X509OperatorPrincipalResolver(
            @Value("${datawallet.intermediate.revoke.operator-ou:operators}") String requiredOu) {
        this.requiredOu = requiredOu;
    }

    @Override
    public Optional<String> resolve(HttpServletRequest request) {
        Object attribute = request.getAttribute(CERT_ATTRIBUTE);
        if (!(attribute instanceof X509Certificate[] certs) || certs.length == 0) {
            return Optional.empty();
        }
        String name = certs[0].getSubjectX500Principal().getName();
        if (name.contains("OU=" + requiredOu)) {
            return Optional.of(name);
        }
        return Optional.empty();
    }
}
