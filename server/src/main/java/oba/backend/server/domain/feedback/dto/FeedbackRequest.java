package oba.backend.server.domain.feedback.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class FeedbackRequest {

    @NotBlank(message = "피드백 내용은 필수입니다.")
    @Size(max = 1000, message = "피드백은 1000자를 초과할 수 없습니다.")
    private String content;
}
