package oba.backend.server.doma.quiz.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SolvedArticleResponse {
    private Long articleId;
    private String title;
    private String summary;
    private String solvedAt;
}
