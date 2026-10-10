package com.vault.config;

import com.vault.security.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * HTTP Basic for a 1-2 day mini-project: simple in Postman, easy viva story.
 * - /api/auth/register + /api/auth/login are PUBLIC
 * - everything else (incl. future /api/files/**) requires authentication
 * - CSRF disabled: this is a stateless JSON API, not a browser form app
 */
@Configuration
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(
            CustomUserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/register", "/api/auth/login", "/error").permitAll()
                .anyRequest().authenticated())
            .httpBasic(Customizer.withDefaults())
            .cors(cors -> cors.configurationSource(corsSource()));
        return http.build();
    }

    /** Vite dev server (5173) calls the API directly with Basic Auth. */
    @Bean
    public org.springframework.web.cors.CorsConfigurationSource corsSource() {
        org.springframework.web.cors.CorsConfiguration c =
                new org.springframework.web.cors.CorsConfiguration();
        c.setAllowedOrigins(java.util.List.of("http://localhost:5173"));
        c.setAllowedMethods(java.util.List.of("GET", "POST", "DELETE", "OPTIONS"));
        c.setAllowedHeaders(java.util.List.of("Authorization", "Content-Type"));
        c.setAllowCredentials(false);
        org.springframework.web.cors.UrlBasedCorsConfigurationSource s =
                new org.springframework.web.cors.UrlBasedCorsConfigurationSource();
        s.registerCorsConfiguration("/api/**", c);
        return s;
    }
}
