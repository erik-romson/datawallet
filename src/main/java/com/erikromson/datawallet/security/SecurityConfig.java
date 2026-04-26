package com.erikromson.datawallet.security;

import com.erikromson.datawallet.domain.SessionRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public BearerAuthFilter bearerAuthFilter(SessionRepository sessionRepository) {
        return new BearerAuthFilter(sessionRepository);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, BearerAuthFilter bearerAuthFilter,
                                           CorsConfigurationSource corsConfigurationSource) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .headers(headers -> headers.cacheControl(cache -> cache.disable()))
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                )
                .addFilterBefore(bearerAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/v1/verifiers").permitAll()
                        .requestMatchers(HttpMethod.GET, "/v1/verifiers/*/login-blob").permitAll()
                        .requestMatchers(HttpMethod.POST, "/v1/auth/challenge").permitAll()
                        .requestMatchers(HttpMethod.POST, "/v1/auth/verify").permitAll()
                        .requestMatchers(HttpMethod.GET, "/v1/directory/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/actuator/health/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/v1/admin/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/v1/admin/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/v1/entries").permitAll()
                        .requestMatchers(HttpMethod.PUT, "/v1/entries/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/v1/entries").permitAll()
                        .requestMatchers(HttpMethod.POST, "/v1/issuers/**").permitAll()
                        .anyRequest().authenticated()
                );
        return http.build();
    }
}
