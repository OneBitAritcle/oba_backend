package oba.backend.server.common.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import oba.backend.server.dto.TokenResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtProvider {

    private final SecretKey key;
    private final long accessTokenValidity;   // ms 단위
    private final long refreshTokenValidity;  // ms 단위

    public JwtProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-token-expiration-ms}") long accessTokenValidity,
            @Value("${jwt.refresh-token-expiration-ms}") long refreshTokenValidity
    ) {
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
        this.accessTokenValidity = accessTokenValidity;
        this.refreshTokenValidity = refreshTokenValidity;
    }

    // =====================
    // Token 생성 (초 단위 exp/iat)
    // =====================
    private String createToken(Long userId, String identifier, long validityMs) {

        long nowSec = System.currentTimeMillis() / 1000;           // 현재 시간 sec
        long expSec = nowSec + (validityMs / 1000);                // 만료 sec

        return Jwts.builder()
                .claim("userId", userId)
                .setSubject(identifier)
                .claim("iat", nowSec)        // 초 단위 issuedAt
                .claim("exp", expSec)        // 초 단위 expiration
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public String createAccessToken(Long userId, String identifier) {
        return createToken(userId, identifier, accessTokenValidity);
    }

    public String createRefreshToken(Long userId, String identifier) {
        return createToken(userId, identifier, refreshTokenValidity);
    }

    public TokenResponse generateTokens(Long userId, String identifier) {
        return new TokenResponse(
                createAccessToken(userId, identifier),
                createRefreshToken(userId, identifier)
        );
    }

    // =====================
    // Token Parsing
    // =====================
    public boolean validateToken(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public Claims getClaims(String token) {
        return parseClaims(token).getBody();
    }

    private Jws<Claims> parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token);
    }

    public Long getUserId(String token) {
        return getClaims(token).get("userId", Long.class);
    }

    public String getIdentifier(String token) {
        return getClaims(token).getSubject();
    }

    // =====================
    // Resolve Token
    // =====================
    public String resolveToken(HttpServletRequest request) {
        String bearer = request.getHeader("Authorization");
        if (bearer == null || !bearer.startsWith("Bearer ")) return null;
        return bearer.substring(7);
    }

    // =====================
    // Authentication 생성
    // =====================
    public org.springframework.security.core.Authentication getAuthentication(String identifier) {

        org.springframework.security.core.userdetails.UserDetails user =
                org.springframework.security.core.userdetails.User.builder()
                        .username(identifier)
                        .password("")     // JWT 인증에서는 비밀번호 사용하지 않음
                        .authorities("USER")
                        .build();

        return new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                user, "", user.getAuthorities()
        );
    }
}
