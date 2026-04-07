package oba.backend.server.global.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain)
            throws ServletException, IOException {

        String token = jwtProvider.resolveToken(request);

        if (token != null) {
            try {
                if (jwtProvider.validateToken(token)) {
                    Claims claims = jwtProvider.getClaims(token);
                    String identifier = claims.getSubject();
                    if (identifier != null && !identifier.isBlank()) {
                        Authentication auth = jwtProvider.getAuthentication(identifier);
                        SecurityContextHolder.getContext().setAuthentication(auth);
                    }
                }
            } catch (ExpiredJwtException e) {
                log.debug("만료된 JWT 토큰: {}", e.getMessage());
            } catch (JwtException e) {
                log.warn("잘못된 JWT 토큰: {}", e.getMessage());
            } catch (Exception e) {
                log.error("JWT 인증 처리 중 오류: {}", e.getMessage());
            }
        }

        chain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/oauth2/") || path.startsWith("/login/") || path.equals("/favicon.ico");
    }
}
