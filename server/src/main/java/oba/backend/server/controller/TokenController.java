package oba.backend.server.controller;

import lombok.RequiredArgsConstructor;
import oba.backend.server.common.jwt.JwtProvider;
import oba.backend.server.domain.user.User;
import oba.backend.server.repository.user.UserRepository;
import oba.backend.server.dto.TokenResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class TokenController {

    private final JwtProvider jwtProvider;
    private final UserRepository userRepository;

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestHeader("Authorization") String refreshToken) {

        String token = refreshToken.replace("Bearer ", "");

        // RefreshToken 검증
        if (!jwtProvider.validateToken(token)) {
            return ResponseEntity.status(401).body("Invalid Refresh Token");
        }

        // JWT 내부 정보 추출
        Long userId = jwtProvider.getUserId(token);
        String identifier = jwtProvider.getIdentifier(token);

        User user = userRepository.findByIdentifier(identifier)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // 새 토큰 발급 (userId + identifier)
        String newAccess = jwtProvider.createAccessToken(userId, identifier);
        String newRefresh = jwtProvider.createRefreshToken(userId, identifier);

        return ResponseEntity.ok(new TokenResponse(newAccess, newRefresh));
    }
}
