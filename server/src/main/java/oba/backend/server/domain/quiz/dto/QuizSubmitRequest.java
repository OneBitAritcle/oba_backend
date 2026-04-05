package oba.backend.server.domain.quiz.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@NoArgsConstructor
public class QuizSubmitRequest {

    @NotBlank(message = "articleId는 필수입니다.")
    private String articleId;

    @NotEmpty(message = "답변 목록은 비어있을 수 없습니다.")
    @Size(min = 1, max = 10, message = "답변은 1~10개 사이여야 합니다.")
    private List<Integer> answers;
}
