package com.example.cua_hang_xe_may.security;

import com.example.cua_hang_xe_may.entities.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

public class JwtUtil {
    private static final String SECRET_KEY = "your_very_long_secret_key_at_least_32_bytes";
    private static final long EXPIRATION_TIME = 864_000_000; // 10 ngày
    private static final SecretKey key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));

    // Cập nhật phương thức generateToken để nhận thêm role
    public static String generateToken(String username, String role) {
        return Jwts.builder()
                .subject(username) // Đặt username vào subject
                .claim("role", role) // Thêm role vào payload
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(key)
                .compact();
    }

    // Overloaded method to accept Role enum
    public static String generateToken(String username, Role role) {
        return generateToken(username, role.getAuthority());
    }

    public static String getUsernameFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return claims.getSubject();
    }

    // Thêm phương thức để lấy role từ token
    public static String getRoleFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return claims.get("role", String.class);
    }

    public static boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}