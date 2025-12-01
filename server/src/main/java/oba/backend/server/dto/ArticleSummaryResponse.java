package oba.backend.server.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class ArticleSummaryResponse {

    private Long articleId;
    private String title;
    private List<String> summaryBullets;
    private String servingDate;
}
