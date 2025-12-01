package oba.backend.server.security.oauth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import oba.backend.server.common.jwt.JwtProvider;
import oba.backend.server.security.oauth.dto.CustomOAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtProvider jwtProvider;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException {

        CustomOAuth2User user = (CustomOAuth2User) authentication.getPrincipal();
        String identifier = "oauth:" + user.getUserId();

        String access = jwtProvider.createAccessToken(identifier);
        String refresh = jwtProvider.createRefreshToken(identifier);

        // 🔥 Expo Redirect URI
        String redirect = "exp://localhost:8081/oauth"
                + "?access=" + access
                + "&refresh=" + refresh;

        getRedirectStrategy().sendRedirect(request, response, redirect);
    }
}