package com.erikromson.datawallet.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

/**
 * Security chain for operator mTLS admin endpoints. Active only when
 * {@code datawallet.security.admin-mtls=true} (the production default).
 * Intercepts admin paths before the verifier bearer chain.
 */
@Configuration
@ConditionalOnProperty(name = "datawallet.security.admin-mtls", havingValue = "true", matchIfMissing = true)
public class AdminSecurityConfig {

    private final String adminOu;

    public AdminSecurityConfig(@Value("${datawallet.security.admin-ou:operators}") String adminOu) {
        this.adminOu = adminOu;
    }

    @Bean
    @Order(2)
    public SecurityFilterChain adminFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/v1/admin/**")
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .headers(headers -> headers.cacheControl(cache -> cache.disable()))
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                )
                .x509(x509 -> x509.subjectPrincipalRegex("(.*?)"))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/v1/admin/directory").authenticated()
                        .requestMatchers(HttpMethod.POST, "/v1/admin/root-update").authenticated()
                        .requestMatchers(HttpMethod.GET, "/v1/admin/audit").authenticated()
                        .anyRequest().denyAll()
                );
        return http.build();
    }
}
