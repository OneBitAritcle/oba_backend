package oba.backend.server.domain.feedback.controller;

import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.feedback.dto.FeedbackRequest;
import oba.backend.server.domain.feedback.dto.FeedbackResponse;
import oba.backend.server.domain.feedback.service.FeedbackService;
import oba.backend.server.global.auth.jwt.JwtProvider;
import oba.backend.server.global.response.ApiResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

@Tag(name = "Feedback", description = "고객 소리함(피드백) 관련 API")
@RestController
@RequestMapping("/api/feedback")
@RequiredArgsConstructor
public class FeedbackController {

    private final FeedbackService feedbackService;
    private final JwtProvider jwtProvider;

    @Operation(summary = "피드백 제출", description = "사용자의 의견(건의사항)을 제출받아 MongoDB에 저장합니다.")
    @PostMapping
    public ResponseEntity<ApiResponse<Object>> submitFeedback(
            @RequestHeader("Authorization") String token,
            @RequestBody FeedbackRequest request) {
        try {
            String accessToken = token.startsWith("Bearer ") ? token.substring(7) : token;
            Long userId = jwtProvider.getUserId(accessToken);

            FeedbackResponse response = feedbackService.saveFeedback(userId, request);

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(ApiResponse.success("피드백이 성공적으로 저장되었습니다.", response));

        } catch (IllegalArgumentException e) {
            String message = "요청 형식이 올바르지 않음";
            if ("CONTENT_EMPTY".equals(e.getMessage())) {
                message = "피드백 내용이 비어있음";
            } else if ("CONTENT_TOO_LONG".equals(e.getMessage())) {
                message = "피드백 내용이 너무 길어요";
            }
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.error(e.getMessage(), message));
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("INTERNAL_ERROR", "서버 오류"));
        }
    }
}
