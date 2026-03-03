package oba.backend.server.domain.report.dto;

import lombok.Builder;
import lombok.Getter;

import java.util.List;

@Getter
@Builder
public class ReportAllResponse {
    private ReportStatsResponse stats;
    private ProgressResponse progress;
    private List<DailyStatResponse> dailyStats;
    private List<CategoryProgressResponse> categoryProgress;
}
