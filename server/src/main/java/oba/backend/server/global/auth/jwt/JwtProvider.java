package oba.backend.server.global.auth.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import oba.backend.server.global.auth.dto.TokenResponse;
import oba.backend.server.global.exception.BusinessException;
import oba.backend.server.global.exception.ErrorCode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import javax.crypto.SecretKey;
import java.util.Collections;
import java.util.Date;

@Slf4j
@Component
public class JwtProvider {

    private final SecretKey key;
    private final long accessTokenValidity;
    private final long refreshTokenValidity;

    public JwtProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-token-expiration-ms}") long accessTokenValidity,
            @Value("${jwt.refresh-token-expiration-ms}") long refreshTokenValidity
    ) {
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
        this.accessTokenValidity = accessTokenValidity;
        this.refreshTokenValidity = refreshTokenValidity;
    }

    private String createToken(Long userId, String identifier, long validityMs) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .claim("userId", userId)
                .setSubject(identifier)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + validityMs))
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

    public boolean validateToken(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (ExpiredJwtException e) {
            log.debug("만료된 JWT 토큰");
            return false;
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("유효하지 않은 JWT 토큰");
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
        Claims claims = getClaims(token);
        Long userId = claims.get("userId", Long.class);
        if (userId == null) {
            throw new BusinessException(ErrorCode.INVALID_TOKEN, "userId가 토큰에 없습니다.");
        }
        return userId;
    }

    public String getIdentifier(String token) {
        return getClaims(token).getSubject();
    }

    public String resolveToken(HttpServletRequest request) {
        String bearer = request.getHeader("Authorization");
        if (bearer == null || !bearer.startsWith("Bearer ") || bearer.length() <= 7) {
            return null;
        }
        return bearer.substring(7).trim();
    }

    public Authentication getAuthentication(String identifier) {
        UserDetails user = User.builder()
                .username(identifier)
                .password("")
                .authorities("ROLE_USER")
                .build();
        return new UsernamePasswordAuthenticationToken(user, "", user.getAuthorities());
    }

    public Long extractUserIdFromHeader(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ") || authorizationHeader.length() <= 7) {
            throw new BusinessException(ErrorCode.INVALID_TOKEN);
        }
        String token = authorizationHeader.substring(7).trim();
        if (!validateToken(token)) {
            throw new BusinessException(ErrorCode.TOKEN_EXPIRED);
        }
        return getUserId(token);
    }
}
