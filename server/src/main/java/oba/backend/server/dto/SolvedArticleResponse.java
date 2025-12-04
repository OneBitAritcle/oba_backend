package oba.backend.server.domain.quiz.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SolvedArticleResponse {
    private Long articleId;
    private String title;
    private String summary;
    private String solvedAt;
}
