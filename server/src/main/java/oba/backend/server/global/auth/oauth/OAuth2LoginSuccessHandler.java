package oba.backend.server.global.auth.oauth;

import lombok.RequiredArgsConstructor;
import oba.backend.server.global.auth.jwt.JwtProvider;
import oba.backend.server.domain.user.entity.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtProvider jwtProvider;

    @Value("${app.mobile-redirect}")
    private String mobileRedirectUri;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException {

        CustomOAuth2User customUser = (CustomOAuth2User) authentication.getPrincipal();
        User user = customUser.getUser();

        String access = jwtProvider.createAccessToken(user.getId(), user.getIdentifier());
        String refresh = jwtProvider.createRefreshToken(user.getId(), user.getIdentifier());

        String redirectUri = mobileRedirectUri
                + "?access=" + URLEncoder.encode(access, StandardCharsets.UTF_8)
                + "&refresh=" + URLEncoder.encode(refresh, StandardCharsets.UTF_8);

        response.sendRedirect(redirectUri);
    }
}
