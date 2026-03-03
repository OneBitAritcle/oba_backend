package oba.backend.server.domain.report.dto;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class ProgressResponse {
    private int solvedCount;
    private int totalCount;
    private int progressPercentage;
}
