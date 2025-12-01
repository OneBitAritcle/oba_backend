package oba.backend.server.common.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;

    // 🔥 JWT를 적용하지 않을 경로들
    private static final List<String> EXCLUDE_URLS = List.of(
            "/articles",
            "/auth",
            "/oauth2",
            "/public",
            "/gpt",
            "/ai"
    );

    private boolean isExcluded(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return EXCLUDE_URLS.stream().anyMatch(uri::startsWith);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        // 1️⃣ 허용 경로는 JWT 검증 건너뛰기 (중요!)
        if (isExcluded(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        // 2️⃣ Access Token 확인
        String accessToken = resolveAccessToken(request);
        String refreshToken = getCookie(request, "refresh_token");

        if (accessToken != null && jwtProvider.validateToken(accessToken)) {
            authenticate(accessToken);
            filterChain.doFilter(request, response);
            return;
        }

        // 3️⃣ Access 만료 + Refresh 정상 → 재발급
        if (refreshToken != null && jwtProvider.validateToken(refreshToken)) {

            var claims = jwtProvider.getClaims(refreshToken);

            if (!"refresh".equals(claims.get("type"))) {
                filterChain.doFilter(request, response);
                return;
            }

            String username = claims.getSubject();
            String newAccessToken = jwtProvider.createAccessToken(username);

            Cookie cookie = new Cookie("access_token", newAccessToken);
            cookie.setHttpOnly(true);
            cookie.setPath("/");
            cookie.setMaxAge(60 * 30);
            response.addCookie(cookie);

            authenticate(newAccessToken);

            filterChain.doFilter(request, response);
            return;
        }

        // 4️⃣ 둘 다 없으면 인증 없이 통과
        filterChain.doFilter(request, response);
    }

    private String resolveAccessToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");

        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }

        return getCookie(request, "access_token");
    }

    private void authenticate(String token) {
        Authentication auth = jwtProvider.getAuthentication(token);
        SecurityContextHolder.getContext().setAuthentication(auth);
    }

    private String getCookie(HttpServletRequest request, String name) {
        if (request.getCookies() == null) return null;

        return Arrays.stream(request.getCookies())
                .filter(c -> name.equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }
}
