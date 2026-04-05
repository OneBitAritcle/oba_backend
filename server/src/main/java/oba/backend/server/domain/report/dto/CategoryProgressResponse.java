package oba.backend.server.domain.report.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@AllArgsConstructor
public class CategoryProgressResponse {
    private int categoryId;
    private String category;
    private int progress;
    private int totalQuizzes;
    private int correctQuizzes;
    private String color;
}
