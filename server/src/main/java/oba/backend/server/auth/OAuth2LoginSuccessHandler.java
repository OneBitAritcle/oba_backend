package oba.backend.server.auth;

import lombok.RequiredArgsConstructor;
import oba.backend.server.common.jwt.JwtProvider;
import oba.backend.server.domain.user.User;
import oba.backend.server.repository.user.UserRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtProvider jwtProvider;
    private final UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        String identifier;

        if (oAuth2User.getAttribute("sub") != null) {
            identifier = "google:" + oAuth2User.getAttribute("sub");
        } else if (oAuth2User.getAttribute("id") != null) {
            identifier = "kakao:" + oAuth2User.getAttribute("id");
        } else {
            Map<String, Object> resp = (Map<String, Object>) oAuth2User.getAttribute("response");
            identifier = "naver:" + resp.get("id");
        }

        User user = userRepository.findByIdentifier(identifier)
                .orElseThrow(() -> new RuntimeException("OAuth2 user not found"));

        String access = jwtProvider.createAccessToken(user.getId(), user.getIdentifier());
        String refresh = jwtProvider.createRefreshToken(user.getId(), user.getIdentifier());

        // 👉 iOS/Android 앱으로 리다이렉트
        String redirectUrl = "myapp://oauth2redirect"
                + "?access=" + access
                + "&refresh=" + refresh;

        response.sendRedirect(redirectUrl);
    }
}
