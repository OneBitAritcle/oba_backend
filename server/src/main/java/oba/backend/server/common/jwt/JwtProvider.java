package oba.backend.server.common.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import oba.backend.server.dto.TokenResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;

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
        // BASE64 decode (반드시 Base64 로 인코딩 후 .env 에 저장해야 함)
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
        this.accessTokenValidity = accessTokenValidity;
        this.refreshTokenValidity = refreshTokenValidity;
    }

    public TokenResponse generateToken(Authentication authentication) {
        String accessToken = createToken(authentication.getName(), "access", accessTokenValidity);
        String refreshToken = createToken(authentication.getName(), "refresh", refreshTokenValidity);
        return new TokenResponse(accessToken, refreshToken);
    }

    public String createAccessToken(String username) {
        return createToken(username, "access", accessTokenValidity);
    }

    public String createRefreshToken(String username) {
        return createToken(username, "refresh", refreshTokenValidity);
    }

    private String createToken(String username, String type, long validity) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + validity);

        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiry)
                .claim("type", type)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public Claims getClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
    }

    public Authentication getAuthentication(String token) {
        Claims claims = getClaims(token);
        String username = claims.getSubject();

        var authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));

        User principal = new User(username, "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }
}
