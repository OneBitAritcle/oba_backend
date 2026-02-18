package oba.backend.server.security;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import oba.backend.server.common.jwt.JwtProvider;
import oba.backend.server.dto.TokenResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final JwtProvider jwtProvider;

    @Override
    public void onAuthenticationSuccess(
            jakarta.servlet.http.HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException {

        TokenResponse tokens = jwtProvider.generateToken(authentication);

        // ✅ Refresh Token (7일, HttpOnly + Secure + SameSite)
        Cookie refreshCookie = new Cookie("refresh_token", tokens.refreshToken());
        refreshCookie.setHttpOnly(true);
        refreshCookie.setSecure(true);
        refreshCookie.setPath("/");
        refreshCookie.setMaxAge(7 * 24 * 60 * 60);
        refreshCookie.setAttribute("SameSite", "None");
        response.addCookie(refreshCookie);

        // ✅ Access Token (30분, HttpOnly + Secure + SameSite)
        Cookie accessCookie = new Cookie("access_token", tokens.accessToken());
        accessCookie.setHttpOnly(true);
        accessCookie.setSecure(true);
        accessCookie.setPath("/");
        accessCookie.setMaxAge(30 * 60);
        accessCookie.setAttribute("SameSite", "None");
        response.addCookie(accessCookie);

        // ✅ 리디렉트 시 토큰 전달 금지 → 상태만 표시
        response.sendRedirect("/login?success=true");
    }
}
