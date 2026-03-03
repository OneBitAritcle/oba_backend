package oba.backend.server.domain.report.dto;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class DailyStatResponse {
    private String date;
    private String day;
    private int accuracy;
    private int attemptedQuizzes;
    private int correctQuizzes;
}
