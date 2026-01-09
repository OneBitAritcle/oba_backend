package oba.backend.server.controller;

import lombok.RequiredArgsConstructor;
import oba.backend.server.doma.quiz.dto.SolvedArticleResponse;
import oba.backend.server.doma.quiz.dto.WrongArticleResponse;
import oba.backend.server.doma.quiz.service.QuizQueryService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/my")
@RequiredArgsConstructor
public class MyQuizController {

    private final QuizQueryService quizQueryService;

    @GetMapping("/solved")
    public ResponseEntity<List<SolvedArticleResponse>> getSolved(@RequestParam Long userId) {
        return ResponseEntity.ok(quizQueryService.getSolved(userId));
    }

    @GetMapping("/wrong")
    public ResponseEntity<List<WrongArticleResponse>> getWrong(@RequestParam Long userId) {
        return ResponseEntity.ok(quizQueryService.getWrong(userId));
    }
}
