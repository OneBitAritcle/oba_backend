package oba.backend.server.domain.report.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@AllArgsConstructor
public class ReportProgressResponse {
    private int solvedCount;
    private int totalCount;
    private int progressPercentage;
}
