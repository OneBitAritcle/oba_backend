package oba.backend.server.controller;

import lombok.RequiredArgsConstructor;
import oba.backend.server.common.jwt.JwtProvider;
import oba.backend.server.dto.LoginRequest;
import oba.backend.server.dto.TokenResponse;
import oba.backend.server.domain.user.User;
import oba.backend.server.repository.user.UserRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class MobileAuthController {

    private final JwtProvider jwtProvider;
    private final UserRepository userRepository;

    @PostMapping("/mobile/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest request) {

        String identifier = "mobile:" + request.getIdToken();

        // 회원 조회 or 생성
        User user = userRepository.findByIdentifier(identifier)
                .orElseGet(() -> userRepository.save(
                        User.createMobileUser(identifier)
                ));

        // JWT 생성 — userId 포함!
        TokenResponse tokens = jwtProvider.generateTokens(
                user.getId(),
                identifier
        );

        return ResponseEntity.ok(tokens);
    }
}
