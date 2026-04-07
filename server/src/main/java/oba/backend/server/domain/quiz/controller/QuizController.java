package oba.backend.server.domain.quiz.controller;

import jakarta.validation.Valid;
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
    private final QuizQueryService quizQueryService;
    private final JwtProvider jwtProvider;

    @PostMapping("/result")
    public ResponseEntity<Void> saveQuizResult(
            @RequestHeader("Authorization") String token,
            @Valid @RequestBody QuizResultRequest request) {

        Long userId = jwtProvider.extractUserIdFromHeader(token);
        quizResultService.saveQuizResult(userId, request);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/wrong")
    public ResponseEntity<List<WrongArticleResponse>> getWrongArticles(
            @RequestHeader("Authorization") String token) {

        Long userId = jwtProvider.extractUserIdFromHeader(token);
        return ResponseEntity.ok(quizQueryService.getWrong(userId));
    }
}
