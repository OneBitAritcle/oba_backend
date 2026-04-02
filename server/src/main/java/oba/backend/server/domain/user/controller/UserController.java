package oba.backend.server.domain.user.controller;

import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.quiz.service.QuizQueryService;
import oba.backend.server.domain.user.dto.UserResponse;
import oba.backend.server.domain.user.entity.User;
import oba.backend.server.domain.user.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final QuizQueryService quizQueryService;

    @GetMapping("/me")
    public ResponseEntity<UserResponse> getMyInfo(@AuthenticationPrincipal UserDetails userDetails) {
        if (userDetails == null) {
            return ResponseEntity.status(401).build();
        }

        String identifier = userDetails.getUsername();
        User user = userService.findByIdentifier(identifier);

        if (user == null) {
            return ResponseEntity.notFound().build();
        }

        // 이번 주 학습 로그 조회
        List<Boolean> weeklyLog = quizQueryService.getWeeklyLog(user.getId());

        // DTO 생성 (weeklyLog 포함)
        return ResponseEntity.ok(UserResponse.from(user, weeklyLog));
    }
}