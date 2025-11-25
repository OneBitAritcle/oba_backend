package oba.backend.server.entity.mongo;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.util.List;

@Document(collection = "Documents")
@Data
public class GptDocument {

    @Id
    private String id;

    // Mongo 필드: article_id
    // Java 필드: articleId
    @Field("article_id")
    private Long articleId;

    private String title;

    @Field("publish_time")
    private String publishTime;

    @Field("serving_date")
    private String servingDate;

    @Field("content_col")
    private Object contentCol;

    @Field("sub_col")
    private Object subCol;

    @Field("gpt_result")
    private GptResult gptResult;

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
}
