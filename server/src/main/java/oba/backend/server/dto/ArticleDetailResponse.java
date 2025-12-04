package oba.backend.server.domain.quiz.dto;

import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Getter
@Builder
public class ArticleDetailResponse {
    private Long articleId;
    private String title;
    private LocalDateTime publishTime;
    private LocalDateTime servingDate;
    private String content;
    private String subtitle;
    private String summary;
    private List<String> keywords;
    private List<Map<String, Object>> quizzes;
}
