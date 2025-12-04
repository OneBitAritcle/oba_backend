package oba.backend.server.domain.quiz.dto;

import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;
import java.util.List;

@Getter
@Builder
public class ArticleSummaryResponse {
    private Long articleId;
    private String title;
    private List<String> summaryBullets;
    private LocalDateTime servingDate;
}
