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
        private Object answer;
        private String explanation;

        public int getAnswerIndex() {
            try {
                if (answer == null) return -1;

                // 1. answer가 숫자 타입이면 바로 인덱스로 사용
                if (answer instanceof Number) {
                    int idx = ((Number) answer).intValue();
                    if (idx >= 0 && idx < options.size()) {
                        return idx;
                    }
                    return -1;
                }

                String cleanAnswer = answer.toString().trim();

                // 2. 숫자 문자열 파싱 (0~3 인덱스)
                String numericPart = cleanAnswer.replaceAll("[^0-9]", "");
                if (!numericPart.isEmpty() && numericPart.length() <= 2) {
                    int num = Integer.parseInt(numericPart);
                    if (num >= 0 && num <= 3 && num < options.size()) {
                        return num;
                    }
                }

                // 3. 정확한 텍스트 매칭
                for (int i = 0; i < options.size(); i++) {
                    if (options.get(i).trim().equals(cleanAnswer)) {
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