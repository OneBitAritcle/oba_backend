package oba.backend.server.domain.feedback.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.feedback.dto.FeedbackRequest;
import oba.backend.server.domain.feedback.entity.Feedback;
import oba.backend.server.domain.feedback.repository.FeedbackRepository;
import oba.backend.server.global.auth.jwt.JwtProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/feedback")
@RequiredArgsConstructor
public class FeedbackController {

    private final FeedbackRepository feedbackRepository;
    private final JwtProvider jwtProvider;

    @PostMapping
    public ResponseEntity<Map<String, String>> submitFeedback(
            @RequestHeader("Authorization") String token,
            @Valid @RequestBody FeedbackRequest request) {

        Long userId = jwtProvider.extractUserIdFromHeader(token);
        String content = request.getContent().trim();

        feedbackRepository.save(Feedback.builder()
                .userId(userId)
                .content(content)
                .build());

        return ResponseEntity.ok(Map.of("message", "피드백이 저장되었습니다."));
    }
}
