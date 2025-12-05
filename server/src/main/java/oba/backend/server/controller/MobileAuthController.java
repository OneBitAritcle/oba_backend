package oba.backend.server.controller;

import lombok.RequiredArgsConstructor;
import oba.backend.server.common.jwt.JwtProvider;
import oba.backend.server.dto.LoginRequest;
import oba.backend.server.dto.TokenResponse;
import oba.backend.server.service.MobileAuthService;
import oba.backend.server.domain.user.User;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class MobileAuthController {

    private final JwtProvider jwtProvider;
    private final MobileAuthService mobileAuthService;

    @PostMapping("/mobile/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest request) {

        String identifier = "mobile:" + request.getIdToken();

        User user = mobileAuthService.findOrCreateMobileUser(identifier);

        TokenResponse tokens = jwtProvider.generateTokens(
                user.getId(),
                user.getIdentifier()
        );

        return ResponseEntity.ok(tokens);
    }
}
