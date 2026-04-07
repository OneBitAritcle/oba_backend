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

    @Field("category_name")
    private List<String> categoryName;

    @Field("content_col")
    private List<List<String>> contentCol;

    @Field("gpt_result")
    private GptResult gptResult;

    // --- 편의 메서드 ---
    public List<String> getContent() {
        if (contentCol == null) return new ArrayList<>();
        return contentCol.stream().flatMap(List::stream).collect(Collectors.toList());
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
                // 1. 텍스트 매칭 우선 (옵션 텍스트와 answer 비교)
                String cleanAnswer = answer.trim();
                for (int i = 0; i < options.size(); i++) {
                    String option = options.get(i).trim();
                    if (option.equals(cleanAnswer) || option.contains(cleanAnswer) || cleanAnswer.contains(option)) {
                        return i;
                    }
                }
                // 2. 텍스트 매칭 실패 시 숫자 파싱 (예: "1)", "2)" 형식)
                String numericPart = answer.replaceAll("[^0-9]", "");
                if (!numericPart.isEmpty() && numericPart.length() <= 2) {
                    int idx = Integer.parseInt(numericPart) - 1;
                    if (idx >= 0 && idx < options.size()) {
                        return idx;
                    }
                }
            } catch (Exception e) {
                return -1;
            }
            return -1;
        }
    }
}