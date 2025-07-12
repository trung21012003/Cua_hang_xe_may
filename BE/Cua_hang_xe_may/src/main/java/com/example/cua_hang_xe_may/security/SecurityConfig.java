package com.example.cua_hang_xe_may.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private final JwtRequestFilter jwtRequestFilter;
    private final UserDetailsService userDetailsService;

    public SecurityConfig(JwtRequestFilter jwtRequestFilter, UserDetailsService userDetailsService) {
        this.jwtRequestFilter = jwtRequestFilter;
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints
                        .requestMatchers("/api/auth/**").permitAll()
                        .requestMatchers("/api/products/public/**").permitAll()
                        .requestMatchers("/api/files/**").permitAll()
                        .requestMatchers("/api/payment/vnpay-return").permitAll()
                        .requestMatchers("/api/test/**").permitAll()
                        .requestMatchers("/api/comments/public/**").permitAll()
                        
                        // Admin only endpoints
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .requestMatchers("/api/products/admin/**").hasRole("ADMIN")
                        .requestMatchers("/api/accounts/admin/**").hasRole("ADMIN")
                        
                        // Manager and Admin endpoints
                        .requestMatchers("/api/manager/**").hasAnyRole("ADMIN", "MANAGER")
                        .requestMatchers("/api/orders/admin/**").hasAnyRole("ADMIN", "MANAGER")
                        .requestMatchers("/api/products/manage/**").hasAnyRole("ADMIN", "MANAGER")
                        
                        // User endpoints (authenticated users)
                        .requestMatchers("/api/profile/**").hasAnyRole("USER", "ADMIN", "MANAGER")
                        .requestMatchers("/api/cart/**").hasAnyRole("USER", "ADMIN", "MANAGER")
                        .requestMatchers("/api/orders/**").hasAnyRole("USER", "ADMIN", "MANAGER")
                        .requestMatchers("/api/comments/**").hasAnyRole("USER", "ADMIN", "MANAGER")
                        
                        // Default: require authentication
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()));

        return http.build();
    }

    // Định nghĩa CorsConfigurationSource cho SecurityFilterChain
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedOriginPattern("http://localhost:[*]");
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
