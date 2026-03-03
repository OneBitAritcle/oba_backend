package oba.backend.server.domain.article.entity;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Document(collection = "Selected_Articles")
public class SelectedArticle {

    @Id
    private String id;

    @Field("article_id")
    private Long articleId;

    private String title;

    @Field("serving_date")
    private String servingDate;

    @Field("publish_time")
    private String publishTime;

    @Field("content_col")
    private List<List<String>> contentCol;

    @Field("gpt_result")
    private GptResult gptResult;

    // --- 편의 메서드 ---
    public List<String> getContent() {
        if (contentCol == null) return new ArrayList<>();
        return contentCol.stream().flatMap(List::stream).collect(Collectors.toList());
    }

    public String getFirstImageUrl() {
        for (String line : getContent()) {
            if (line != null && line.trim().startsWith("<img>")) {
                return line.trim().replace("<img>", "").trim();
            }
        }
        return null;
    }

    public List<String> getSummaryBullets() {
        if (gptResult != null && gptResult.getSummary() != null) {
            String rawSummary = gptResult.getSummary();
            return rawSummary.contains("\n") ? Arrays.asList(rawSummary.split("\n")) : List.of(rawSummary);
        }
        return new ArrayList<>();
    }

    public List<KeywordItem> getKeywordItems() {
        if (gptResult == null || gptResult.getKeywords() == null) return new ArrayList<>();
        return gptResult.getKeywords();
    }

    public List<QuizItem> getQuizzes() {
        return (gptResult != null) ? gptResult.quizzes : new ArrayList<>();
    }

    // --- 내부 클래스 ---
    @Getter @Setter @NoArgsConstructor @AllArgsConstructor
    public static class GptResult {
        private String summary;
        private List<KeywordItem> keywords;
        private List<QuizItem> quizzes;
    }

    @Getter @Setter @NoArgsConstructor @AllArgsConstructor
    public static class KeywordItem {
        private String keyword;
        private String description;
    }

    @Getter @Setter @NoArgsConstructor @AllArgsConstructor
    public static class QuizItem {
        private String question;
        private List<String> options;
        private String answer;
        private String explanation;

        public int getAnswerIndex() {
            try {
                if (answer == null) return -1;
                String numericPart = answer.replaceAll("[^0-9]", "");
                if (!numericPart.isEmpty() && numericPart.length() < 3) {
                    return Integer.parseInt(numericPart) - 1;
                }
                for (int i = 0; i < options.size(); i++) {
                    String option = options.get(i).trim();
                    String cleanAnswer = answer.trim();
                    if (option.equals(cleanAnswer) || option.contains(cleanAnswer) || cleanAnswer.contains(option)) {
                        return i;
                    }
                }
            } catch (Exception e) {
                return -1;
            }
            return -1;
        }
    }
}