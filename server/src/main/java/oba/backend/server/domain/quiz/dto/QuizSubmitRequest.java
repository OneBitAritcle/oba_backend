package oba.backend.server.doma.quiz.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import java.util.List;

@Getter
@NoArgsConstructor
public class QuizSubmitRequest {
    private Long articleId;
    private List<Integer> answers; // 0 or 1
}
