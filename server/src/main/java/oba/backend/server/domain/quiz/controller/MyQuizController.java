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
@RequestMapping("/api/my")
@RequiredArgsConstructor
public class MyQuizController {

    private final QuizQueryService quizQueryService;
    private final JwtProvider jwtProvider;

    @GetMapping("/solved")
    public ResponseEntity<List<SolvedArticleResponse>> getSolved(
            @RequestHeader("Authorization") String token) {
        Long userId = jwtProvider.extractUserIdFromHeader(token);
        return ResponseEntity.ok(quizQueryService.getSolved(userId));
    }

    @GetMapping("/wrong")
    public ResponseEntity<List<WrongArticleResponse>> getWrong(
            @RequestHeader("Authorization") String token) {
        Long userId = jwtProvider.extractUserIdFromHeader(token);
        return ResponseEntity.ok(quizQueryService.getWrong(userId));
    }
}
