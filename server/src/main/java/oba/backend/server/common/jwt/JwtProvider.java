package oba.backend.server.common.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import oba.backend.server.dto.TokenResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtProvider {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.access-token-expiration-ms}")
    private long accessTokenValidity;

    @Value("${jwt.refresh-token-expiration-ms}")
    private long refreshTokenValidity;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
    }

    /* 인증 헤더에서 토큰 추출 */
    public String resolveToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }

    /* Claims 파싱 */
    public Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /* 유효성 검사 */
    public boolean validateToken(String token) {
        try {
            getClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    /* Access Token 생성 */
    public String createAccessToken(Long userId, String identifier) {
        long now = System.currentTimeMillis();

        return Jwts.builder()
                .setSubject(identifier)              // sub = provider:xxxx
                .claim("userId", userId)             // payload: userId
                .claim("type", "access")             // token type
                .setExpiration(new Date(now + accessTokenValidity))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /* Refresh Token 생성 */
    public String createRefreshToken(Long userId, String identifier) {
        long now = System.currentTimeMillis();

        return Jwts.builder()
                .setSubject(identifier)
                .claim("userId", userId)
                .claim("type", "refresh")
                .setExpiration(new Date(now + refreshTokenValidity))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /* Access + Refresh 묶음 */
    public TokenResponse generateTokens(Long userId, String identifier) {
        return new TokenResponse(
                createAccessToken(userId, identifier),
                createRefreshToken(userId, identifier)
        );
    }

    /* JWT → userId 추출 */
    public Long getUserId(String token) {
        return getClaims(token).get("userId", Long.class);
    }

    /* JWT → identifier 추출 */
    public String getIdentifier(String token) {
        return getClaims(token).getSubject();
    }

    /* Spring Security Authentication 생성 */
    public Authentication getAuthentication(String identifier) {
        User user = new User(
                identifier,
                "",
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        return new UsernamePasswordAuthenticationToken(
                user, "", user.getAuthorities()
        );
    }
}
