package oba.backend.server.domain.quiz.service;

import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.article.entity.SelectedArticle;
import oba.backend.server.domain.article.repository.GptMongoRepository;
import oba.backend.server.domain.log.entity.ArticleLog;
import oba.backend.server.domain.log.repository.ArticleLogRepository;
import oba.backend.server.domain.quiz.dto.QuizResultRequest;
import oba.backend.server.domain.quiz.entity.IncorrectQuiz;
import oba.backend.server.domain.quiz.repository.IncorrectQuizRepository;
import oba.backend.server.domain.report.service.ReportService;
import oba.backend.server.domain.stats.entity.UserCategoryId;
import oba.backend.server.domain.stats.entity.UserCategoryStats;
import oba.backend.server.domain.stats.repository.UserCategoryStatsRepository;
import oba.backend.server.domain.user.entity.User;
import oba.backend.server.domain.user.repository.UserRepository;
import oba.backend.server.global.exception.BusinessException;
import oba.backend.server.global.exception.ErrorCode;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class QuizResultService {

    private final UserRepository userRepository;
    private final IncorrectQuizRepository incorrectQuizRepository;
    private final ArticleLogRepository articleLogRepository;
    private final GptMongoRepository gptMongoRepository;
    private final UserCategoryStatsRepository userCategoryStatsRepository;

    @Transactional
    public void saveQuizResult(Long userId, QuizResultRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        user.updateStreak();

        SelectedArticle article = gptMongoRepository.findById(request.getArticleId())
                .orElseThrow(() -> new BusinessException(ErrorCode.ARTICLE_NOT_FOUND));

        Long numericArticleId = article.getArticleId();
        if (numericArticleId == null) {
            throw new BusinessException(ErrorCode.ARTICLE_NOT_FOUND, "기사의 숫자 ID가 없습니다.");
        }

        // 학습 로그 저장/갱신
        ArticleLog log = articleLogRepository.findById(
                        new oba.backend.server.domain.log.entity.ArticleLogId(userId, numericArticleId))
                .orElseGet(() -> ArticleLog.builder()
                        .userId(userId)
                        .articleId(numericArticleId)
                        .build());

        if (!request.getResults().contains(false)) {
            log.markAsResolved();
        }
        articleLogRepository.save(log);

        // 오답 기록 저장
        IncorrectQuiz quizRecord = incorrectQuizRepository
                .findByUserIdAndArticleId(userId, numericArticleId)
                .orElseGet(() -> IncorrectQuiz.builder()
                        .userId(userId)
                        .articleId(numericArticleId)
                        .build());

        quizRecord.setQuizResults(request.getResults());
        incorrectQuizRepository.save(quizRecord);

        // 카테고리별 통계 업데이트
        updateCategoryStats(userId, article, request.getResults());

        // 퍼펙트 데이 체크 (오늘 기사 5개 이상 풀었는지)
        LocalDateTime todayStart = LocalDate.now().atStartOfDay();
        int todaySolved = articleLogRepository.findByUserIdAndInitialAtGreaterThanEqual(userId, todayStart).size();
        user.getUserStats().checkAndUpdatePerfectDay(todaySolved);
    }

    private void updateCategoryStats(Long userId, SelectedArticle article, List<Boolean> results) {
        List<String> categories = article.getCategoryName();
        if (categories == null || categories.isEmpty()) return;

        int totalQ = results.size();
        int correctQ = (int) results.stream().filter(Boolean::booleanValue).count();

        for (String category : categories) {
            int categoryId = ReportService.categorySlugToId(category);
            UserCategoryId key = new UserCategoryId(userId, categoryId);
            UserCategoryStats catStats = userCategoryStatsRepository.findById(key)
                    .orElseGet(() -> UserCategoryStats.builder()
                            .userId(userId)
                            .categoryId(categoryId)
                            .build());
            catStats.addScore(totalQ, correctQ);
            userCategoryStatsRepository.save(catStats);
        }
    }
}
