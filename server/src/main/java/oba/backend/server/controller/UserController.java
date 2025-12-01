package oba.backend.server.security.oauth;

import lombok.RequiredArgsConstructor;
import oba.backend.server.common.jwt.JwtProvider;
import oba.backend.server.domain.user.User;
import oba.backend.server.domain.user.UserRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;
    private final JwtProvider jwtProvider;

    @GetMapping("/me")
    public ResponseEntity<?> me(@RequestHeader("Authorization") String bearer) {

        String token = bearer.replace("Bearer ", "");
        String identifier = jwtProvider.getUserId(token);

        User user = userRepository.findByIdentifier(identifier)
                .orElseThrow();

        // DTO로 반환
        return ResponseEntity.ok(new UserProfileResponse(
                user.getIdentifier(),
                user.getEmail(),
                user.getName(),
                user.getPicture(),
                user.getProvider().name()
        ));
    }

    public record UserProfileResponse(
            String identifier,
            String email,
            String name,
            String picture,
            String provider
    ) {}
}
