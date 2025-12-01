package oba.backend.server.controller;

import lombok.RequiredArgsConstructor;
import oba.backend.server.common.jwt.JwtProvider;
import oba.backend.server.domain.quiz.dto.SolvedArticleResponse;
import oba.backend.server.domain.quiz.dto.WrongArticleResponse;
import oba.backend.server.service.QuizQueryService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/my")
@RequiredArgsConstructor
public class MyQuizController {

    private final QuizQueryService quizQueryService;
    private final JwtProvider jwtProvider;

    private Long extractUserId(String token) {
        String jwt = token.replace("Bearer ", "");
        String subject = jwtProvider.getClaims(jwt).getSubject(); // google:123
        return Long.valueOf(subject.split(":")[1]);
    }

    @GetMapping("/solved")
    public ResponseEntity<List<SolvedArticleResponse>> solved(
            @RequestHeader("Authorization") String token
    ) {
        Long userId = extractUserId(token);
        return ResponseEntity.ok(quizQueryService.getSolved(userId));
    }

    @GetMapping("/wrong")
    public ResponseEntity<List<WrongArticleResponse>> wrong(
            @RequestHeader("Authorization") String token
    ) {
        Long userId = extractUserId(token);
        return ResponseEntity.ok(quizQueryService.getWrong(userId));
    }
}