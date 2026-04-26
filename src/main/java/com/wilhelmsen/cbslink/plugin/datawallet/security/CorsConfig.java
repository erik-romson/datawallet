package com.wilhelmsen.cbslink.plugin.datawallet.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * Strict CORS configuration allowing only the configured web origin.
 * Never uses wildcard origins.
 */
@Configuration
public class CorsConfig {

    private final String webOrigin;

    public CorsConfig(@Value("${datawallet.web-origin:}") String webOrigin) {
        this.webOrigin = webOrigin;
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        if (!webOrigin.isBlank()) {
            config.setAllowedOrigins(List.of(webOrigin));
        }
        config.setAllowCredentials(false);
        config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "OPTIONS"));
        config.setMaxAge(600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
