package oba.backend.server.domain.report.controller;

import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.report.dto.*;
import oba.backend.server.domain.report.service.ReportService;
import oba.backend.server.global.auth.jwt.JwtProvider;
import oba.backend.server.global.response.ApiResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

import java.util.List;

@Tag(name = "Report", description = "학습 리포트 관련 API")
@RestController
@RequestMapping("/api/report")
@RequiredArgsConstructor
public class ReportController {

    private final ReportService reportService;
    private final JwtProvider jwtProvider;

    private Long extractUserId(String token) {
        String jwt = token.startsWith("Bearer ") ? token.substring(7) : token;
        return jwtProvider.getUserId(jwt);
    }

    @Operation(summary = "사용자 통계 조회", description = "연속 학습일, 최고 기록, 퍼펙트 데이 등의 통계를 조회합니다.")
    @GetMapping("/stats")
    public ResponseEntity<ApiResponse<ReportStatsResponse>> getStats(
            @RequestHeader("Authorization") String token) {
        Long userId = extractUserId(token);
        ReportStatsResponse response = reportService.getStats(userId);
        return ResponseEntity.ok(ApiResponse.success("통계 조회 성공", response));
    }

    @Operation(summary = "전체 학습 진도 조회", description = "전체 문제 중 푼 문제 수와 진도율을 조회합니다.")
    @GetMapping("/progress")
    public ResponseEntity<ApiResponse<ProgressResponse>> getProgress(
            @RequestHeader("Authorization") String token) {
        Long userId = extractUserId(token);
        ProgressResponse response = reportService.getProgress(userId);
        return ResponseEntity.ok(ApiResponse.success("진도 조회 성공", response));
    }

    @Operation(summary = "요일별 정답률 조회", description = "최근 7일(기본값) 동안의 요일별 정답률을 조회합니다.")
    @GetMapping("/daily-stats")
    public ResponseEntity<ApiResponse<List<DailyStatResponse>>> getDailyStats(
            @RequestHeader("Authorization") String token,
            @RequestParam(name = "days", defaultValue = "7") int days) {
        Long userId = extractUserId(token);
        List<DailyStatResponse> response = reportService.getDailyStats(userId, days);
        return ResponseEntity.ok(ApiResponse.success("요일별 정답률 조회 성공", response));
    }

    @Operation(summary = "카테고리별 정답률 조회", description = "각 카테고리별 정답률과 색상을 조회합니다.")
    @GetMapping("/category-progress")
    public ResponseEntity<ApiResponse<List<CategoryProgressResponse>>> getCategoryProgress(
            @RequestHeader("Authorization") String token) {
        Long userId = extractUserId(token);
        List<CategoryProgressResponse> response = reportService.getCategoryProgress(userId);
        return ResponseEntity.ok(ApiResponse.success("카테고리별 정답률 조회 성공", response));
    }

    @Operation(summary = "전체 리포트 통합 조회", description = "통계, 진도, 요일별, 카테고리별 데이터를 한 번에 조회합니다.")
    @GetMapping("/all")
    public ResponseEntity<ApiResponse<ReportAllResponse>> getAllReportData(
            @RequestHeader("Authorization") String token,
            @RequestParam(name = "days", defaultValue = "7") int days) {
        Long userId = extractUserId(token);
        ReportAllResponse response = reportService.getAllReportData(userId, days);
        return ResponseEntity.ok(ApiResponse.success("전체 리포트 조회 성공", response));
    }
}
