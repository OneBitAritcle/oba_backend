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

    private Object content;         // 원본 배열 구조 유지
    private Object subtitle;        // 원본 배열 구조 유지

    private String summary;
    private List<String> keywords;

    private List<Map<String, Object>> quizzes;
}
