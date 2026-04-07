package oba.backend.server.global.auth.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.user.entity.User;
import oba.backend.server.domain.user.service.UserService;
import oba.backend.server.global.auth.dto.LoginRequest;
import oba.backend.server.global.auth.dto.TokenResponse;
import oba.backend.server.global.auth.jwt.JwtProvider;
import oba.backend.server.global.auth.oauth.OAuth2UserInfo;
import oba.backend.server.global.exception.BusinessException;
import oba.backend.server.global.exception.ErrorCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final JwtProvider jwtProvider;
    private final UserService userService;

    @PostMapping("/mobile/login")
    public ResponseEntity<TokenResponse> mobileLogin(@Valid @RequestBody LoginRequest request) {
        OAuth2UserInfo userInfo = OAuth2UserInfo.builder()
                .id(request.getIdToken())
                .email(request.getIdToken() + "@mobile.user")
                .name("모바일유저")
                .provider("MOBILE")
                .build();

        User user = userService.registerOrUpdateUser(userInfo);
        return ResponseEntity.ok(jwtProvider.generateTokens(user.getId(), user.getIdentifier()));
    }

    @PostMapping("/reissue")
    public ResponseEntity<TokenResponse> reissue(@RequestHeader("Authorization") String refreshHeader) {
        if (refreshHeader == null || !refreshHeader.startsWith("Bearer ") || refreshHeader.length() <= 7) {
            throw new BusinessException(ErrorCode.INVALID_TOKEN);
        }

        String token = refreshHeader.substring(7).trim();
        if (!jwtProvider.validateToken(token)) {
            throw new BusinessException(ErrorCode.TOKEN_EXPIRED);
        }

        Long userId = jwtProvider.getUserId(token);
        String identifier = jwtProvider.getIdentifier(token);
        return ResponseEntity.ok(jwtProvider.generateTokens(userId, identifier));
    }
}
