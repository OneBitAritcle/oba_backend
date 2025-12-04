package oba.backend.server.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import java.util.List;

@Getter
@NoArgsConstructor
public class QuizSubmitRequest {
    private Long articleId;
    private List<Integer> answers;  // 0 또는 1 값
}
