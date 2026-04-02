package oba.backend.server.domain.quiz.controller;

import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.quiz.dto.QuizResultRequest;
import oba.backend.server.domain.quiz.dto.WrongArticleResponse;
import oba.backend.server.domain.quiz.service.QuizQueryService;
import oba.backend.server.domain.quiz.service.QuizResultService;
import oba.backend.server.global.auth.jwt.JwtProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/quiz")
@RequiredArgsConstructor
public class QuizController {

    private final QuizResultService quizResultService;
    private final QuizQueryService quizQueryService; // 조회 서비스 추가
    private final JwtProvider jwtProvider; // 토큰 처리용

    // 1. 퀴즈 결과 저장
    @PostMapping("/result")
    public ResponseEntity<String> saveQuizResult(
            @RequestHeader("Authorization") String token,
            @RequestBody QuizResultRequest request) {

        String accessToken = token.startsWith("Bearer ") ? token.substring(7) : token;
        quizResultService.saveQuizResult(accessToken, request);
        return ResponseEntity.ok("저장 완료");
    }

    // 2. 오답 노트 조회
    @GetMapping("/wrong")
    public ResponseEntity<List<WrongArticleResponse>> getWrongArticles(
            @RequestHeader("Authorization") String token) {

        String accessToken = token.startsWith("Bearer ") ? token.substring(7) : token;
        Long userId = jwtProvider.getUserId(accessToken);

        return ResponseEntity.ok(quizQueryService.getWrong(userId));
    }
}