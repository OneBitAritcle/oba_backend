package oba.backend.server.auth;

import lombok.RequiredArgsConstructor;
import oba.backend.server.common.jwt.JwtProvider;
import oba.backend.server.domain.user.User;
import oba.backend.server.repository.user.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtProvider jwtProvider;
    private final UserRepository userRepository;

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

        // JWT 생성
        String access = jwtProvider.createAccessToken(user.getId(), user.getIdentifier());
        String refresh = jwtProvider.createRefreshToken(user.getId(), user.getIdentifier());

        String redirectUri = mobileRedirectUri
                + "?access=" + access
                + "&refresh=" + refresh;

        response.sendRedirect(redirectUri);
    }
}
