package oba.backend.server.dto;

import lombok.Builder;
import lombok.Getter;

import java.util.List;
import java.util.Map;

@Getter
@Builder
public class ArticleDetailResponse {
    private Long articleId;
    private String title;
    private String publishTime;
    private String servingDate;
    private String content;
    private String subtitle;
    private String summary;
    private List<String> keywords;
    private List<Map<String, Object>> quizzes;
}
