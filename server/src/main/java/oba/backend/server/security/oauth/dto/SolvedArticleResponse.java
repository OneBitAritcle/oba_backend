package oba.backend.server.domain.quiz.dto;

import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
@Builder
public class SolvedArticleResponse {
    private Long articleId;
    private LocalDateTime solvedAt;
}
