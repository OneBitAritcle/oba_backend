package oba.backend.server.domain.user.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.quiz.service.QuizQueryService;
import oba.backend.server.domain.user.dto.NicknameRequest;
import oba.backend.server.domain.user.dto.UserResponse;
import oba.backend.server.domain.user.entity.User;
import oba.backend.server.domain.user.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final QuizQueryService quizQueryService;

    @GetMapping("/me")
    public ResponseEntity<UserResponse> getMyInfo(@AuthenticationPrincipal UserDetails userDetails) {
        User user = userService.findByIdentifier(userDetails.getUsername());
        List<Boolean> weeklyLog = quizQueryService.getWeeklyLog(user.getId());
        return ResponseEntity.ok(UserResponse.from(user, weeklyLog));
    }

    @PutMapping("/nickname")
    public ResponseEntity<Map<String, String>> updateNickname(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody NicknameRequest request) {
        userService.updateNickname(userDetails.getUsername(), request.getNickname());
        return ResponseEntity.ok(Map.of("message", "닉네임이 수정되었습니다.", "nickname", request.getNickname()));
    }
}
