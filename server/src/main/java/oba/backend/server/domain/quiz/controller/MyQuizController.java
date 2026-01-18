package oba.backend.server.domain.quiz.controller;

import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.quiz.dto.SolvedArticleResponse;
import oba.backend.server.domain.quiz.dto.WrongArticleResponse;
import oba.backend.server.domain.quiz.service.QuizQueryService;
import oba.backend.server.global.auth.jwt.JwtProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/my") // 혹은 /api/users/me
@RequiredArgsConstructor
public class MyQuizController {

    private final QuizQueryService quizQueryService;
    private final JwtProvider jwtProvider;

    // 내가 푼 문제 목록
    @GetMapping("/solved")
    public ResponseEntity<List<SolvedArticleResponse>> getSolved(
            @RequestHeader("Authorization") String token) {
        Long userId = extractUserId(token);
        return ResponseEntity.ok(quizQueryService.getSolved(userId));
    }

    // 나의 오답 노트
    @GetMapping("/wrong")
    public ResponseEntity<List<WrongArticleResponse>> getWrong(
            @RequestHeader("Authorization") String token) {
        Long userId = extractUserId(token);
        return ResponseEntity.ok(quizQueryService.getWrong(userId));
    }

    // 토큰 파싱 헬퍼 메서드
    private Long extractUserId(String token) {
        String jwt = token.startsWith("Bearer ") ? token.substring(7) : token;
        return jwtProvider.getUserId(jwt);
    }
}