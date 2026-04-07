package oba.backend.server.domain.report.service;

import lombok.RequiredArgsConstructor;
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

import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.LocalDateTime;
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
    private final GptMongoRepository gptMongoRepository;

    // 카테고리 slug → 한글 이름 매핑
    private static final Map<String, String> CATEGORY_DISPLAY_NAMES = new LinkedHashMap<>() {{
        put("artificial-intelligence", "인공지능");
        put("generative-ai", "생성형 AI");
        put("cloud-computing", "클라우드 컴퓨팅");
        put("mobile", "모바일");
        put("networking", "네트워크");
        put("android", "안드로이드");
        put("windows", "윈도우");
        put("personal-computing", "퍼스널 컴퓨팅");
        put("computers-and-peripherals", "퍼스널 컴퓨팅");
        put("data-center", "데이터센터");
        put("productivity-software", "생산성 소프트웨어");
        put("emerging-technology", "미래기술");
        put("collaboration-software", "협업 소프트웨어");
        put("augmented-reality", "증강 현실");
        put("security", "보안");
        put("enterprise-applications", "엔터프라이즈 애플리케이션");
        put("software-development", "소프트웨어 개발");
        put("it-leadership", "IT 리더십");
        put("vendors-and-providers", "기술 업계 동향");
        put("it-management", "IT 관리");
        put("apple", "애플");
    }};

    // 카테고리별 고유 색상
    private static final String[] CATEGORY_COLORS_ARRAY = {
        "#87CEEB", "#D4845C", "#D4C9AA", "#A9A9A9", "#7FCD7F",
        "#E8A0BF", "#FFB347", "#B39DDB", "#81C784", "#4FC3F7",
        "#FF8A65", "#AED581", "#F06292", "#FFD54F", "#90CAF9",
        "#CE93D8", "#80CBC4", "#FFAB91", "#A1887F", "#9FA8DA", "#E0E0E0"
    };

    // 카테고리 slug → Integer ID (해시 기반, 안정적 매핑)
    public static int categorySlugToId(String slug) {
        List<String> slugs = new ArrayList<>(CATEGORY_DISPLAY_NAMES.keySet());
        int idx = slugs.indexOf(slug);
        return idx >= 0 ? idx + 1 : Math.abs(slug.hashCode() % 1000) + 100;
    }

    public static String categoryIdToDisplayName(int categoryId) {
        List<String> slugs = new ArrayList<>(CATEGORY_DISPLAY_NAMES.keySet());
        if (categoryId >= 1 && categoryId <= slugs.size()) {
            String slug = slugs.get(categoryId - 1);
            return CATEGORY_DISPLAY_NAMES.get(slug);
        }
        return "기타";
    }

    public static String categoryIdToColor(int categoryId) {
        if (categoryId >= 1 && categoryId <= CATEGORY_COLORS_ARRAY.length) {
            return CATEGORY_COLORS_ARRAY[categoryId - 1];
        }
        return "#CCCCCC";
    }

    public ReportStatsResponse getStats(Long userId) {
        UserStats stats = userStatsRepository.findById(userId).orElse(null);
        if (stats == null) {
            return ReportStatsResponse.builder()
                    .consecutiveDays(0)
                    .maxConsecutiveDays(0)
                    .perfectDays(0)
                    .lastLearnedAt(null)
                    .build();
        }
        return ReportStatsResponse.builder()
                .consecutiveDays(stats.getCurrentStreak())
                .maxConsecutiveDays(stats.getMaxStreak())
                .perfectDays(stats.getTotalPerfectDays())
                .lastLearnedAt(stats.getLastLearnedAt() != null ? stats.getLastLearnedAt().toString() : null)
                .build();
    }

    public ReportProgressResponse getProgress(Long userId) {
        // 사용자가 푼 기사 수 (ArticleLog 기준)
        List<ArticleLog> logs = articleLogRepository.findByUserId(userId);
        int solvedArticles = logs.size();

        // DB 전체 기사 수 (MongoDB)
        long totalArticles = gptMongoRepository.count();

        int percentage = totalArticles > 0 ? (int) Math.round((double) solvedArticles / totalArticles * 100) : 0;
        return ReportProgressResponse.builder()
                .solvedCount(solvedArticles)
                .totalCount((int) totalArticles)
                .progressPercentage(percentage)
                .build();
    }

    private static final Map<DayOfWeek, String> KOREAN_DAY_NAMES = Map.of(
            DayOfWeek.MONDAY, "월",
            DayOfWeek.TUESDAY, "화",
            DayOfWeek.WEDNESDAY, "수",
            DayOfWeek.THURSDAY, "목",
            DayOfWeek.FRIDAY, "금",
            DayOfWeek.SATURDAY, "토",
            DayOfWeek.SUNDAY, "일"
    );

    public List<DailyStatResponse> getDailyStats(Long userId, int days) {
        // 이번 주 월요일~일요일 고정
        LocalDate today = LocalDate.now();
        LocalDate monday = today.with(java.time.temporal.TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY));
        LocalDate sunday = monday.plusDays(6);
        LocalDateTime since = monday.atStartOfDay();

        List<ArticleLog> logs = articleLogRepository.findByUserId(userId);
        List<IncorrectQuiz> quizzes = incorrectQuizRepository.findByUserId(userId);

        Map<Long, IncorrectQuiz> quizMap = quizzes.stream()
                .collect(Collectors.toMap(IncorrectQuiz::getArticleId, q -> q, (a, b) -> b));

        // 월~일 7일 고정 맵
        Map<LocalDate, int[]> dailyMap = new LinkedHashMap<>();
        for (int i = 0; i < 7; i++) {
            dailyMap.put(monday.plusDays(i), new int[]{0, 0});
        }

        for (ArticleLog log : logs) {
            if (log.getInitialAt() == null || log.getInitialAt().isBefore(since)) continue;
            LocalDate date = log.getInitialAt().toLocalDate();
            if (!dailyMap.containsKey(date)) continue;

            IncorrectQuiz quiz = quizMap.get(log.getArticleId());
            if (quiz != null) {
                List<Boolean> results = quiz.getQuizResults();
                int attempted = results.size();
                int correct = (int) results.stream().filter(Boolean::booleanValue).count();
                dailyMap.get(date)[0] += attempted;
                dailyMap.get(date)[1] += correct;
            }
        }

        DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd");
        List<DailyStatResponse> result = new ArrayList<>();
        for (Map.Entry<LocalDate, int[]> entry : dailyMap.entrySet()) {
            LocalDate date = entry.getKey();
            int[] counts = entry.getValue();
            int accuracy = counts[0] > 0 ? (int) Math.round((double) counts[1] / counts[0] * 100) : 0;
            result.add(DailyStatResponse.builder()
                    .date(date.format(fmt))
                    .day(KOREAN_DAY_NAMES.get(date.getDayOfWeek()))
                    .accuracy(accuracy)
                    .attemptedQuizzes(counts[0])
                    .correctQuizzes(counts[1])
                    .build());
        }
        return result;
    }

    public List<CategoryProgressResponse> getCategoryProgress(Long userId) {
        // 사용자의 실제 데이터
        List<UserCategoryStats> catStats = userCategoryStatsRepository.findByUserId(userId);
        Map<Integer, UserCategoryStats> statsMap = catStats.stream()
                .collect(Collectors.toMap(UserCategoryStats::getCategoryId, cs -> cs));

        // 모든 카테고리를 순회하며 결과 생성
        List<CategoryProgressResponse> result = new ArrayList<>();
        List<String> slugs = new ArrayList<>(CATEGORY_DISPLAY_NAMES.keySet());

        // 중복 한글 이름 방지 (computers-and-peripherals와 personal-computing 모두 "퍼스널 컴퓨팅")
        Set<String> addedNames = new HashSet<>();

        for (int i = 0; i < slugs.size(); i++) {
            int categoryId = i + 1;
            String displayName = CATEGORY_DISPLAY_NAMES.get(slugs.get(i));
            if (addedNames.contains(displayName)) continue;
            addedNames.add(displayName);

            UserCategoryStats stats = statsMap.get(categoryId);
            int totalQ = stats != null ? stats.getTotalQuizzes() : 0;
            int correctQ = stats != null ? stats.getCorrectQuizzes() : 0;
            int progress = totalQ > 0 ? (int) Math.round((double) correctQ / totalQ * 100) : 0;

            result.add(CategoryProgressResponse.builder()
                    .categoryId(categoryId)
                    .category(displayName)
                    .progress(progress)
                    .totalQuizzes(totalQ)
                    .correctQuizzes(correctQ)
                    .color(categoryIdToColor(categoryId))
                    .build());
        }
        return result;
    }
}
