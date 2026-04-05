package oba.backend.server.domain.quiz.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@NoArgsConstructor
public class QuizResultRequest {

    @NotBlank(message = "articleId는 필수입니다.")
    private String articleId;

    @NotEmpty(message = "퀴즈 결과는 비어있을 수 없습니다.")
    @Size(min = 1, max = 10, message = "퀴즈 결과는 1~10개 사이여야 합니다.")
    private List<Boolean> results;
}
