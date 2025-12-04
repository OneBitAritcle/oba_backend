package oba.backend.server.dto;

import lombok.Builder;
import lombok.Getter;

import java.util.List;

@Getter
@Builder
public class ArticleSummaryResponse {
    private Long articleId;
    private String title;
    private List<String> summaryBullets;
    private String servingDate; // String으로 변경
}
