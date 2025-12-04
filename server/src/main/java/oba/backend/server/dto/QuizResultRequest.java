package oba.backend.server.domain.quiz.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class QuizResultRequest {
    private Long articleId;
    private boolean correct;
    private int selectedOption;
}
