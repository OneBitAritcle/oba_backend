package oba.backend.server.global.auth.controller;

import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.user.entity.User;
import oba.backend.server.domain.user.service.UserService;
import oba.backend.server.global.auth.dto.LoginRequest;
import oba.backend.server.global.auth.dto.TokenResponse;
import oba.backend.server.global.auth.jwt.JwtProvider;
import oba.backend.server.global.auth.oauth.OAuth2UserInfo;
import oba.backend.server.global.common.Const;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final JwtProvider jwtProvider;
    private final UserService userService;

    // 모바일 소셜 로그인
    @PostMapping("/mobile/login")
    public ResponseEntity<TokenResponse> mobileLogin(@RequestBody LoginRequest request) {
        // OAuth2UserInfo 가방에 담아서 서비스에 전달
        OAuth2UserInfo userInfo = OAuth2UserInfo.builder()
                .id(request.getIdToken())
                .email(request.getIdToken() + "@mobile.user")
                .name("모바일유저")
                .provider("MOBILE") // AuthProvider.MOBILE로 매핑
                .build();

        User user = userService.registerOrUpdateUser(userInfo);

        return ResponseEntity.ok(jwtProvider.generateTokens(user.getId(), user.getIdentifier()));
    }

    // 토큰 재발급
    @PostMapping("/reissue")
    public ResponseEntity<TokenResponse> reissue(@RequestHeader("Authorization") String refreshHeader) {
        if (refreshHeader == null || !refreshHeader.startsWith(Const.BEARER_PREFIX)) {
            return ResponseEntity.badRequest().build();
        }

        String token = refreshHeader.substring(Const.BEARER_PREFIX.length());

        if (!jwtProvider.validateToken(token)) {
            return ResponseEntity.status(401).build();
        }

        Long userId = jwtProvider.getUserId(token);
        String identifier = jwtProvider.getIdentifier(token);

        return ResponseEntity.ok(jwtProvider.generateTokens(userId, identifier));
    }
}