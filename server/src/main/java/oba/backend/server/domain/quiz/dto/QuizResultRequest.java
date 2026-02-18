package oba.backend.server.domain.quiz.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import java.util.List;

@Getter
@NoArgsConstructor
public class QuizResultRequest {
    private String articleId;
    private List<Boolean> results;
}