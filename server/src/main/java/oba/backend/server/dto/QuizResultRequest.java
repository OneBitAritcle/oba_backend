package oba.backend.server.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class QuizResultRequest {
    private Long articleId;
    private boolean correct;        // 맞았는지
    private int selectedOption;     // 사용자가 고른 선택지
}
