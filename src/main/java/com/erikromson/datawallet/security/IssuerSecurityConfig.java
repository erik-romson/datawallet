package com.erikromson.datawallet.security;

import com.erikromson.datawallet.directory.DirectoryRecordCodec;
import com.erikromson.datawallet.domain.DirectoryRecordRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
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

import java.time.Clock;

@Configuration
public class IssuerSecurityConfig {

    @Value("${datawallet.security.issuer-mtls:true}")
    private boolean issuerMtls;

    @Value("${datawallet.security.issuer-bearer.enabled:false}")
    private boolean issuerBearerEnabled;

    @Value("${datawallet.security.issuer-bearer.audience:urn:datawallet:server}")
    private String issuerBearerAudience;

    @PostConstruct
    void validateIssuerSecurityConfig() {
        if (issuerMtls && issuerBearerEnabled) {
            throw new IssuerSecurityConfigurationError(
                    "issuer-bearer.enabled=true requires issuer-mtls=false");
        }
    }

    @Bean
    @Order(1)
    @ConditionalOnProperty(name = "datawallet.security.issuer-mtls", havingValue = "true", matchIfMissing = true)
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

    @Bean
    @ConditionalOnExpression(
            "${datawallet.security.issuer-mtls:true} == false "
            + "&& ${datawallet.security.issuer-bearer.enabled:false} == true"
    )
    public BearerJwtVerifier bearerJwtVerifier() {
        return new BearerJwtVerifier(Clock.systemUTC());
    }

    @Bean
    @ConditionalOnExpression(
            "${datawallet.security.issuer-mtls:true} == false "
            + "&& ${datawallet.security.issuer-bearer.enabled:false} == true"
    )
    public BearerIssuerPrincipalResolver bearerIssuerPrincipalResolver(
            DirectoryRecordRepository directoryRecordRepository,
            DirectoryRecordCodec codec,
            BearerJwtVerifier bearerJwtVerifier) {
        return new BearerIssuerPrincipalResolver(
                directoryRecordRepository, codec, bearerJwtVerifier, issuerBearerAudience);
    }

    public static class IssuerSecurityConfigurationError extends RuntimeException {
        public IssuerSecurityConfigurationError(String message) {
            super(message);
        }
    }
}
