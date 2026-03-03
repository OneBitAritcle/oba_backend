package oba.backend.server.domain.report.service;

import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.article.entity.SelectedArticle;
import oba.backend.server.domain.article.repository.GptMongoRepository;
import oba.backend.server.domain.log.entity.ArticleLog;
import oba.backend.server.domain.log.repository.ArticleLogRepository;
import oba.backend.server.domain.quiz.entity.IncorrectQuiz;
import oba.backend.server.domain.quiz.repository.IncorrectQuizRepository;
import oba.backend.server.domain.report.dto.*;
import oba.backend.server.domain.stats.entity.UserCategoryStats;
import oba.backend.server.domain.stats.entity.UserStats;
import oba.backend.server.domain.stats.repository.UserCategoryStatsRepository;
import oba.backend.server.domain.stats.repository.UserStatsRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class ReportService {

    private final UserStatsRepository userStatsRepository;
    private final UserCategoryStatsRepository userCategoryStatsRepository;
    private final ArticleLogRepository articleLogRepository;
    private final IncorrectQuizRepository incorrectQuizRepository;

    // 카테고리 매핑용 임시 상수
    private static final Map<Integer, String> CATEGORY_NAMES = Map.of(
            1, "Tech",
            2, "AI",
            3, "Health",
            4, "Social",
            5, "Pizza"
    );
    private static final Map<Integer, String> CATEGORY_COLORS = Map.of(
            1, "#87CEEB",
            2, "#D4845C",
            3, "#D4C9AA",
            4, "#A9A9A9",
            5, "#7FCD7F"
    );

    // 1️⃣ 사용자 통계 조회
    public ReportStatsResponse getStats(Long userId) {
        UserStats userStats = userStatsRepository.findById(userId).orElse(null);

        if (userStats == null) {
            return ReportStatsResponse.builder()
                    .consecutiveDays(0)
                    .maxConsecutiveDays(0)
                    .perfectDays(0)
                    .lastLearnedAt(null)
                    .build();
        }

        return ReportStatsResponse.builder()
                .consecutiveDays(userStats.getCurrentStreak())
                .maxConsecutiveDays(userStats.getMaxStreak())
                .perfectDays(userStats.getTotalPerfectDays())
                .lastLearnedAt(userStats.getLastLearnedAt() != null ? userStats.getLastLearnedAt().toString() : null)
                .build();
    }

    // 2️⃣ 전체 학습 진도 조회
    public ProgressResponse getProgress(Long userId) {
        List<UserCategoryStats> categoryStatsList = userCategoryStatsRepository.findByUserId(userId);

        int totalCount = categoryStatsList.stream().mapToInt(UserCategoryStats::getTotalQuizzes).sum();
        int solvedCount = categoryStatsList.stream().mapToInt(UserCategoryStats::getCorrectQuizzes).sum();

        int progressPercentage = totalCount == 0 ? 0 : (int) Math.floor(((double) solvedCount / totalCount) * 100);

        return ProgressResponse.builder()
                .solvedCount(solvedCount)
                .totalCount(totalCount)
                .progressPercentage(progressPercentage)
                .build();
    }

    // 3️⃣ 요일별 정답률 조회
    public List<DailyStatResponse> getDailyStats(Long userId, int days) {
        if (days < 1 || days > 365) {
            throw new IllegalArgumentException("days parameter must be between 1 and 365");
        }

        List<ArticleLog> allLogs = articleLogRepository.findByUserId(userId);
        List<IncorrectQuiz> allQuizRecords = incorrectQuizRepository.findByUserId(userId);

        LocalDate startDate = LocalDate.now().minusDays(days - 1);
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");

        // 날짜별 (articleId 기준) 매핑 저장용
        Map<String, List<Long>> dateToArticleIds = new HashMap<>();

        for (ArticleLog log : allLogs) {
            LocalDate logDate = log.getInitialAt().toLocalDate();
            if (!logDate.isBefore(startDate)) {
                String dateStr = logDate.format(formatter);
                dateToArticleIds.computeIfAbsent(dateStr, k -> new ArrayList<>()).add(log.getArticleId());
            }
        }

        List<DailyStatResponse> result = new ArrayList<>();
        // 최근 N일부터 오늘까지 순회
        for (int i = days - 1; i >= 0; i--) {
            LocalDate targetDate = LocalDate.now().minusDays(i);
            String dateStr = targetDate.format(formatter);
            String dayStr = targetDate.getDayOfWeek().toString().substring(0, 3);
            dayStr = dayStr.substring(0, 1).toUpperCase() + dayStr.substring(1).toLowerCase();

            List<Long> articleIdsForDate = dateToArticleIds.getOrDefault(dateStr, new ArrayList<>());

            int attemptedQuizzes = 0;
            int correctQuizzes = 0;

            for (Long articleId : articleIdsForDate) {
                IncorrectQuiz quizRecord = allQuizRecords.stream()
                        .filter(q -> q.getArticleId().equals(articleId))
                        .findFirst().orElse(null);

                if (quizRecord != null) {
                    // 기사 1개당 문제는 5개
                    attemptedQuizzes += 5;
                    correctQuizzes += extractCorrectCount(quizRecord);
                }
            }

            int accuracy = attemptedQuizzes == 0 ? 0 : (int) Math.floor(((double) correctQuizzes / attemptedQuizzes) * 100);

            result.add(DailyStatResponse.builder()
                    .date(dateStr)
                    .day(dayStr)
                    .accuracy(accuracy)
                    .attemptedQuizzes(attemptedQuizzes)
                    .correctQuizzes(correctQuizzes)
                    .build());
        }

        return result;
    }

    // 4️⃣ 카테고리별 정답률 조회
    public List<CategoryProgressResponse> getCategoryProgress(Long userId) {
        List<UserCategoryStats> categoryStatsList = userCategoryStatsRepository.findByUserId(userId);

        List<CategoryProgressResponse> result = categoryStatsList.stream().map(stats -> {
            int categoryId = stats.getCategoryId();
            String categoryName = CATEGORY_NAMES.getOrDefault(categoryId, "Unknown");
            String color = CATEGORY_COLORS.getOrDefault(categoryId, "#CCCCCC");

            int total = stats.getTotalQuizzes();
            int correct = stats.getCorrectQuizzes();
            int progress = total == 0 ? 0 : (int) Math.floor(((double) correct / total) * 100);

            return CategoryProgressResponse.builder()
                    .categoryId(categoryId)
                    .category(categoryName)
                    .progress(progress)
                    .totalQuizzes(total)
                    .correctQuizzes(correct)
                    .color(color)
                    .build();
        }).sorted(Comparator.comparing(CategoryProgressResponse::getCategory)).collect(Collectors.toList());

        return result;
    }

    // 📊 통합 리포트
    public ReportAllResponse getAllReportData(Long userId, int days) {
        return ReportAllResponse.builder()
                .stats(getStats(userId))
                .progress(getProgress(userId))
                .dailyStats(getDailyStats(userId, days))
                .categoryProgress(getCategoryProgress(userId))
                .build();
    }

    // Helper: IncorrectQuiz에서 맞춘 퀴즈 개수 추출
    private int extractCorrectCount(IncorrectQuiz quiz) {
        int count = 0;
        if (quiz.isQuiz1()) count++;
        if (quiz.isQuiz2()) count++;
        if (quiz.isQuiz3()) count++;
        if (quiz.isQuiz4()) count++;
        if (quiz.isQuiz5()) count++;
        return count; // 요구사항: 각 true는 정답으로 처리, (총 문제는 attemptedQuizzes * 5 겠지만 프론트의 accuracy 로직 요구사항대로)
        // 주의: attemptedQuizzes 가 '푼 기사 개수'인지 '문제셋 자체 갯수'인지 확인 필요. 명세서에선 attemptedQuizzes: 풀이한 문제 수 이며 correctQuizzes: 5 라고 함.
        // 하지만 요구사항 상: accuracy = (correctQuizzes / attemptedQuizzes) * 100
        // 이부분의 attemptedQuizzes 는 명세서 예시에 따라 "총 문제 수"를 뜻함.
    }
}
