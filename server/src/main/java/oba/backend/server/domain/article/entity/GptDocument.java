package oba.backend.server.domain.article.entity;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.util.List;

// 1. AI 서버가 저장하는 컬렉션 이름과 정확히 일치 (대소문자 구분)
@Document(collection = "Selected_Articles")
@Data
public class GptDocument {

    @Id
    private String id; // MongoDB ID

    @Field("article_id")
    private Long articleId;

    private String title;

    @Field("publish_time")
    private String publishTime;

    @Field("serving_date")
    private String servingDate;

    @Field("content_col")
    private List<Object> content;

    @Field("sub_col")
    private List<String> subtitle;

    @Field("gpt_result")
    private GptResult gptResult;

    // --- Inner Classes ---
    @Data
    public static class GptResult {
        private String summary;
        private List<Keyword> keywords;
        private List<Quiz> quizzes;

        @Data
        public static class Keyword {
            private String keyword;
            private String description;
        }

        @Data
        public static class Quiz {
            private String question;
            private List<String> options;
            private String answer;
            private String explanation;
        }
    }

    public String getSummary() {
        return gptResult != null ? gptResult.getSummary() : null;
    }

    public List<GptResult.Keyword> getKeywords() {
        return gptResult != null ? gptResult.getKeywords() : null;
    }

    public List<GptResult.Quiz> getQuizzes() {
        return gptResult != null ? gptResult.getQuizzes() : null;
    }
}