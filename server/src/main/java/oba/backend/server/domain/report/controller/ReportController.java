package oba.backend.server.domain.report.controller;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.report.dto.*;
import oba.backend.server.domain.report.service.ReportService;
import oba.backend.server.global.auth.jwt.JwtProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/report")
@RequiredArgsConstructor
public class ReportController {

    private final ReportService reportService;
    private final JwtProvider jwtProvider;

    @GetMapping("/stats")
    public ResponseEntity<ReportStatsResponse> getStats(
            @RequestHeader("Authorization") String token) {
        Long userId = jwtProvider.extractUserIdFromHeader(token);
        return ResponseEntity.ok(reportService.getStats(userId));
    }

    @GetMapping("/progress")
    public ResponseEntity<ReportProgressResponse> getProgress(
            @RequestHeader("Authorization") String token) {
        Long userId = jwtProvider.extractUserIdFromHeader(token);
        return ResponseEntity.ok(reportService.getProgress(userId));
    }

    @GetMapping("/daily-stats")
    public ResponseEntity<List<DailyStatResponse>> getDailyStats(
            @RequestHeader("Authorization") String token,
            @RequestParam(defaultValue = "7") @Min(1) @Max(90) int days) {
        Long userId = jwtProvider.extractUserIdFromHeader(token);
        return ResponseEntity.ok(reportService.getDailyStats(userId, days));
    }

    @GetMapping("/category-progress")
    public ResponseEntity<List<CategoryProgressResponse>> getCategoryProgress(
            @RequestHeader("Authorization") String token) {
        Long userId = jwtProvider.extractUserIdFromHeader(token);
        return ResponseEntity.ok(reportService.getCategoryProgress(userId));
    }
}
