package com.erikromson.datawallet.security;

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
 * Security chain for issuer mTLS endpoints. Active only when
 * {@code datawallet.security.issuer-mtls=true} (the production default).
 * Intercepts issuer paths before the verifier bearer chain.
 */
@Configuration
@ConditionalOnProperty(name = "datawallet.security.issuer-mtls", havingValue = "true", matchIfMissing = true)
public class IssuerSecurityConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain issuerFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/v1/entries/**", "/v1/issuers/**")
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .headers(headers -> headers.cacheControl(cache -> cache.disable()))
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                )
                .x509(x509 -> x509.subjectPrincipalRegex("CN=(.*?)(?:,|$)"))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/v1/entries").authenticated()
                        .requestMatchers(HttpMethod.PUT, "/v1/entries/**").authenticated()
                        .requestMatchers(HttpMethod.GET, "/v1/entries").authenticated()
                        .requestMatchers(HttpMethod.POST, "/v1/issuers/**").authenticated()
                        .anyRequest().denyAll()
                );
        return http.build();
    }
}
