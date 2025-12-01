package oba.backend.server.controller;

import lombok.RequiredArgsConstructor;
import oba.backend.server.dto.QuizSubmitRequest;
import oba.backend.server.service.QuizService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/quiz")
@RequiredArgsConstructor
public class QuizController {

    private final QuizService quizService;

    @PostMapping("/submit")
    public ResponseEntity<?> submitQuiz(
            @RequestHeader("Authorization") String token,
            @RequestBody QuizSubmitRequest request
    ) {
        quizService.submitQuiz(token.replace("Bearer ", ""), request);
        return ResponseEntity.ok().build();
    }
}
