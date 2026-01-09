package oba.backend.server.domain.article.service;

public class QuizAnswerParser {

    /**
     * GPT가 보낸 answer 문자열(예: "2", "정답: 2", "2번")을 0~3 인덱스로 변환
     */
    public static int toIndex(String answer) {
        if (answer == null) return 0;
        String cleaned = answer.replaceAll("[^0-9]", "").trim();

        try {
            int num = Integer.parseInt(cleaned);
            return Math.max(0, Math.min(3, num - 1)); // 1~4 → 0~3
        } catch (Exception e) {
            return 0;
        }
    }
}
