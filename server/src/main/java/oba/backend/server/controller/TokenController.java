package oba.backend.server.controller;

import lombok.RequiredArgsConstructor;
import oba.backend.server.common.jwt.JwtProvider;
import oba.backend.server.dto.TokenResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class TokenController {

    private final JwtProvider jwtProvider;

    @PostMapping("/reissue")
    public ResponseEntity<TokenResponse> reissue(@RequestHeader("Authorization") String refreshHeader) {

        if (!refreshHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().build();
        }

        String token = refreshHeader.substring(7);

        if (!jwtProvider.validateToken(token)) {
            return ResponseEntity.status(401).build();
        }

        Long userId = jwtProvider.getUserId(token);
        String identifier = jwtProvider.getIdentifier(token);

        TokenResponse newTokens = jwtProvider.generateTokens(userId, identifier);

        return ResponseEntity.ok(newTokens);
    }
}
