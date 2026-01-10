package oba.backend.server.domain.article.dto;

import lombok.Builder;
import lombok.Getter;

import java.util.List;

@Getter
@Builder
public class ArticleDetailResponse {

    // 🚨 수정됨: Long -> String
    private String articleId;

    private String title;
    private String publishTime;
    private String servingDate;

    // 본문은 텍스트와 이미지 태그가 섞여 있으므로 Object 리스트
    private List<Object> content;
    private List<String> subtitle;

    private String summary;
    private List<String> keywords;
    private List<QuizDto> quizzes;

    @Getter
    @Builder
    public static class QuizDto {
        private String question;
        private List<String> options;
        private int answer; // 프론트엔드에서는 인덱스(0, 1, 2, 3)를 기대함
        private String explanation;
    }
}