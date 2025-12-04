package oba.backend.server.controller;

import lombok.RequiredArgsConstructor;
import oba.backend.server.dto.QuizResultRequest;
import oba.backend.server.service.QuizResultService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/quiz-result")
@RequiredArgsConstructor
public class QuizResultController {

    private final QuizResultService quizResultService;

    @PostMapping("/save")
    public ResponseEntity<?> saveQuizResult(
            @RequestHeader("Authorization") String token,
            @RequestBody QuizResultRequest request
    ) {
        quizResultService.saveQuizResult(token.replace("Bearer ", ""), request);
        return ResponseEntity.ok().build();
    }
}
