package oba.backend.server.domain.feedback.service;

import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.feedback.dto.FeedbackRequest;
import oba.backend.server.domain.feedback.dto.FeedbackResponse;
import oba.backend.server.domain.feedback.entity.Feedback;
import oba.backend.server.domain.feedback.repository.FeedbackRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Date;

@Service
@RequiredArgsConstructor
public class FeedbackService {

    private final FeedbackRepository feedbackRepository;

    public FeedbackResponse saveFeedback(Long userId, FeedbackRequest request) {
        String content = request.getContent() != null ? request.getContent().trim() : "";

        // Validate content is not empty
        if (content.isEmpty()) {
            throw new IllegalArgumentException("CONTENT_EMPTY");
        }

        // Validate content length <= 700 chars
        if (content.length() > 700) {
            throw new IllegalArgumentException("CONTENT_TOO_LONG");
        }

        Date now = new Date();
        Feedback feedback = Feedback.builder()
                .userId(userId)
                .content(content)
                .submittedAt(now)
                .createdAt(now)
                .status("pending")
                .build();

        Feedback saved = feedbackRepository.save(feedback);

        String isoDate = java.time.ZonedDateTime.ofInstant(saved.getSubmittedAt().toInstant(), ZoneOffset.UTC)
                .format(DateTimeFormatter.ISO_INSTANT);

        return FeedbackResponse.builder()
                .feedbackId(saved.getId())
                .userId(saved.getUserId())
                .content(saved.getContent())
                .submittedAt(isoDate)
                .build();
    }
}
