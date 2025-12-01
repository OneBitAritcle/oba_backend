package oba.backend.server.domain.quiz;

import lombok.Getter;

@Getter
public class QuizResultRequest {
    private Long articleId;
    private boolean[] quizResults;  // true=정답, false=오답
}
