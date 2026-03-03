package oba.backend.server.domain.feedback.dto;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class FeedbackResponse {
    private String feedbackId;
    private Long userId; // Assuming JWT user_id is passed as Long
    private String content;
    private String submittedAt;
}
