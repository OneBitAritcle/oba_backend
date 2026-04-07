package oba.backend.server.domain.quiz.dto;

import lombok.*;

@Getter
@Builder
@AllArgsConstructor
public class WrongArticleResponse {
    private String articleId;
    private String title;
    private String summary;
    private String imageUrl;
    private String category;
    private String solvedAt;
}