package oba.backend.server.global.auth.oauth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import oba.backend.server.domain.user.entity.User;
import oba.backend.server.global.auth.jwt.JwtProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtProvider jwtProvider;

    @Value("${app.mobile-redirect}")
    private String mobileRedirectUri;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {

        CustomOAuth2User customUser = (CustomOAuth2User) authentication.getPrincipal();
        User user = customUser.getUser();

        String identifier = user.getIdentifier();

        String accessToken = jwtProvider.createAccessToken(user.getId(), identifier);
        String refreshToken = jwtProvider.createRefreshToken(user.getId(), identifier);

        log.info("OAuth2 Login Success: User={}, Identifier={}", user.getName(), identifier);

        String targetUrl = UriComponentsBuilder.fromUriString(mobileRedirectUri)
                .queryParam("access_token", accessToken)
                .queryParam("refresh_token", refreshToken)
                .build()
                .encode(StandardCharsets.UTF_8)
                .toUriString();

        clearAuthenticationAttributes(request);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}