package oba.backend.server.global.auth.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.user.entity.User;
import oba.backend.server.domain.user.service.UserService;
import oba.backend.server.global.auth.dto.ChangePasswordRequest;
import oba.backend.server.global.auth.dto.LoginRequest;
import oba.backend.server.global.auth.dto.SignupRequest;
import oba.backend.server.global.auth.dto.TokenResponse;
import oba.backend.server.global.auth.jwt.JwtProvider;
import oba.backend.server.global.exception.BusinessException;
import oba.backend.server.global.exception.ErrorCode;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final JwtProvider jwtProvider;
    private final UserService userService;

    @PostMapping("/signup")
    public ResponseEntity<TokenResponse> signup(@Valid @RequestBody SignupRequest request) {
        User user = userService.register(request.getEmail(), request.getPassword(), request.getName());
        TokenResponse tokens = jwtProvider.generateTokens(user.getId(), user.getIdentifier());
        return ResponseEntity.status(HttpStatus.CREATED).body(tokens);
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
        User user = userService.login(request.getEmail(), request.getPassword());
        TokenResponse tokens = jwtProvider.generateTokens(user.getId(), user.getIdentifier());
        return ResponseEntity.ok(tokens);
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

    @PutMapping("/password")
    public ResponseEntity<Map<String, String>> changePassword(
            @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody ChangePasswordRequest request) {
        Long userId = jwtProvider.extractUserIdFromHeader(authHeader);
        userService.changePassword(userId, request.getCurrentPassword(), request.getNewPassword());
        return ResponseEntity.ok(Map.of("message", "비밀번호가 변경되었습니다."));
    }
}
