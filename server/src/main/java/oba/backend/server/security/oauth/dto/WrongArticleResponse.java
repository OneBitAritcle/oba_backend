package oba.backend.server.domain.quiz.dto;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class WrongArticleResponse {
    private Long articleId;
    private boolean[] wrongList;   // ex: [false, true, false, true, false]
}
