package oba.backend.server.doma.article.dto;

import lombok.Builder;
import lombok.Getter;

import java.util.List;

@Getter
@Builder
public class ArticleSummaryResponse {
    private Long articleId;
    private String title;
    private List<String> summaryBullets;
    private String servingDate;
}
