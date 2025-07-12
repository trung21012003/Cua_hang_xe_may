package com.example.cua_hang_xe_may.security;

import com.example.cua_hang_xe_may.entities.Role;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String path = request.getRequestURI();
        System.out.println("Path: " + request.getRequestURI());
        if (path.startsWith("/api/auth/")) {
            chain.doFilter(request, response);
            return;
        }
        final String authorizationHeader = request.getHeader("Authorization");

        String username = null;
        String jwt = null;

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
            username = JwtUtil.getUsernameFromToken(jwt);
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            if (JwtUtil.validateToken(jwt)) {
                // Get role from JWT token
                String roleFromToken = JwtUtil.getRoleFromToken(jwt);
                Role role = Role.fromAuthority(roleFromToken);
                
                System.out.println("JWT Processing - Username: " + username + ", Role: " + roleFromToken + ", Authority: " + role.getAuthority());
                
                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(
                            username, 
                            null, 
                            Collections.singletonList(new SimpleGrantedAuthority(role.getAuthority()))
                        );
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                
                System.out.println("Authentication set for user: " + username + " with authorities: " + authenticationToken.getAuthorities());
            }
        }
        chain.doFilter(request, response);
    }
}