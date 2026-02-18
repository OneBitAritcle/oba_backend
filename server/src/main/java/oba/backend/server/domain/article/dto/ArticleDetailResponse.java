package oba.backend.server.domain.article.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import oba.backend.server.domain.article.entity.SelectedArticle;

import java.util.List;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ArticleDetailResponse {

    private String articleId;
    private String title;
    private List<String> content;
    private List<String> summaryBullets;
    private List<KeywordDto> keywords;
    private String servingDate;
    private List<SelectedArticle.QuizItem> quizzes;
    private List<Boolean> myQuizResults;

    @Getter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class KeywordDto {
        private String keyword;
        private String description;
    }
}