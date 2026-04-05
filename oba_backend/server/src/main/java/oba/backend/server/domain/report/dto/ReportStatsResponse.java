package oba.backend.server.domain.report.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@AllArgsConstructor
public class ReportStatsResponse {
    private int consecutiveDays;
    private int maxConsecutiveDays;
    private int perfectDays;
    private String lastLearnedAt;
}
