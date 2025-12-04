package oba.backend.server.domain.quiz.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class WrongArticleResponse {
    private Long articleId;
    private String title;
    private String summary;
    private boolean[] incorrectAnswers;
    private String solvedAt;
}
