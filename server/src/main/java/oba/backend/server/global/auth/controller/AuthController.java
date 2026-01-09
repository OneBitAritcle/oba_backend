package oba.backend.server.global.auth.controller;

import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.user.entity.ProviderInfo;
import oba.backend.server.domain.user.entity.Role;
import oba.backend.server.domain.user.entity.User;
import oba.backend.server.global.auth.dto.LoginRequest;
import oba.backend.server.global.auth.dto.TokenResponse;
import oba.backend.server.global.auth.jwt.JwtProvider;
import oba.backend.server.global.common.Const;
import oba.backend.server.domain.user.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final JwtProvider jwtProvider;
    private final UserService userService;

    // 모바일 소셜 로그인 (ID Token 검증은 클라이언트가 했다고 가정)
    @PostMapping("/mobile/login")
    public ResponseEntity<TokenResponse> mobileLogin(@RequestBody LoginRequest request) {
        String identifier = "mobile:" + request.getIdToken();

        // Mobile 유저는 별도 프로필 정보가 없으므로 기본값 사용
        User user = userService.findOrCreateUser(
                identifier,
                identifier + "@mobile.user",
                "모바일유저",
                null,
                ProviderInfo.MOBILE,
                Role.USER
        );

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

        // 토큰에서 정보 추출 후 재발급
        Long userId = jwtProvider.getUserId(token);
        String identifier = jwtProvider.getIdentifier(token);

        return ResponseEntity.ok(jwtProvider.generateTokens(userId, identifier));
    }
}