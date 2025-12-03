package oba.backend.server.controller;

import lombok.RequiredArgsConstructor;
import oba.backend.server.common.jwt.JwtProvider;
import oba.backend.server.dto.LoginRequest;
import oba.backend.server.dto.TokenResponse;
import oba.backend.server.security.oauth.dto.CustomOAuth2User;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class MobileAuthController {

    private final JwtProvider jwtProvider;

    /**
     * 🔥 모바일 앱 구글 로그인
     * Expo → Firebase → Google ID Token → 백엔드 검증 → JWT 발급
     */
    @PostMapping("/google")
    public ResponseEntity<TokenResponse> googleLogin(@RequestBody LoginRequest request) {

        // request.getIdToken() = Firebase Google ID Token
        String googleSubject = jwtProvider.verifyGoogleIdToken(request.getIdToken());
        // 반환 예: "google:123456789"

        // Access + Refresh 동시 발급
        TokenResponse tokens = jwtProvider.generateTokens(googleSubject);

        return ResponseEntity.ok(tokens);
    }

    /**
     * 🔥 OAuth2 (브라우저) 성공 후 JWT 반환용
     * 이 컨트롤러는 모바일 앱에는 사용되지 않지만
     * 기존 웹 로그인 흐름이 필요하면 유지
     */
    @GetMapping("/oauth/success")
    public ResponseEntity<TokenResponse> oauthSuccess(Authentication authentication) {

        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        CustomOAuth2User user = (CustomOAuth2User) oauthToken.getPrincipal();

        // 예: google:12345
        String identifier = "google:" + user.getUserId();

        TokenResponse tokens = jwtProvider.generateTokens(identifier);

        return ResponseEntity.ok(tokens);
    }
}
