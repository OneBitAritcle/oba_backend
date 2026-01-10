package oba.backend.server.domain.article.dto;

import lombok.Builder;
import lombok.Getter;

import java.util.List;

@Getter
@Builder
public class ArticleSummaryResponse {

    private String articleId;

    private String title;
    private List<String> summaryBullets;
    private String servingDate;
}