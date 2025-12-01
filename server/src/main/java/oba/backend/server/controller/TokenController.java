package oba.backend.server.controller;

import lombok.RequiredArgsConstructor;
import oba.backend.server.common.jwt.JwtProvider;
import oba.backend.server.domain.user.User;
import oba.backend.server.domain.user.UserRepository;
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

        if (!jwtProvider.validateToken(token)) {
            return ResponseEntity.status(401).body("Invalid Refresh Token");
        }

        String identifier = jwtProvider.getClaims(token).getSubject();

        User user = userRepository.findByIdentifier(identifier)
                .orElseThrow(() -> new RuntimeException("User not found"));

        String newAccess = jwtProvider.createAccessToken(identifier);
        String newRefresh = jwtProvider.createRefreshToken(identifier);

        return ResponseEntity.ok(new TokenResponse(newAccess, newRefresh));
    }
}
