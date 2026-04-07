package oba.backend.server.domain.quiz.service;

import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.article.entity.SelectedArticle;
import oba.backend.server.domain.article.repository.GptMongoRepository;
import oba.backend.server.domain.log.entity.ArticleLog;
import oba.backend.server.domain.log.repository.ArticleLogRepository;
import oba.backend.server.domain.quiz.dto.SolvedArticleResponse;
import oba.backend.server.domain.quiz.dto.WrongArticleResponse;
import oba.backend.server.domain.quiz.entity.IncorrectQuiz;
import oba.backend.server.domain.quiz.repository.IncorrectQuizRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.temporal.TemporalAdjusters;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class QuizQueryService {

    private final IncorrectQuizRepository incorrectQuizRepository;
    private final GptMongoRepository gptMongoRepository;
    private final ArticleLogRepository articleLogRepository;

    public List<SolvedArticleResponse> getSolved(Long userId) {
        return incorrectQuizRepository.findByUserId(userId).stream()
                .map(record -> {
                    SelectedArticle article = gptMongoRepository.findByArticleId(record.getArticleId())
                            .orElse(null);

                    String title = (article != null) ? article.getTitle() : "삭제된 기사";
                    String mongoId = (article != null) ? article.getId() : "";

                    return SolvedArticleResponse.builder()
                            .articleId(mongoId)
                            .title(title)
                            .solvedAt(LocalDate.now().toString())
                            .build();
                })
                .collect(Collectors.toList());
    }

    public List<WrongArticleResponse> getWrong(Long userId) {
        List<IncorrectQuiz> records = incorrectQuizRepository.findByUserId(userId);
        List<WrongArticleResponse> responseList = new ArrayList<>();

        for (IncorrectQuiz record : records) {
            if (record.getQuizResults().contains(false)) {
                SelectedArticle article = gptMongoRepository.findByArticleId(record.getArticleId())
                        .orElse(null);

                if (article != null) {
                    String summary = (article.getSummaryBullets() != null && !article.getSummaryBullets().isEmpty())
                            ? article.getSummaryBullets().get(0) : "요약 없음";

                    String category = (article.getCategoryName() != null && !article.getCategoryName().isEmpty())
                            ? article.getCategoryName().get(0) : "기타";

                    responseList.add(WrongArticleResponse.builder()
                            .articleId(article.getId())
                            .title(article.getTitle())
                            .summary(summary)
                            .category(category)
                            .solvedAt(LocalDate.now().toString())
                            .build());
                }
            }
        }
        return responseList;
    }

    public List<Boolean> getWeeklyLog(Long userId) {
        LocalDate today = LocalDate.now();
        LocalDate monday = today.with(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY));

        List<ArticleLog> logs = articleLogRepository.findByUserId(userId);
        Set<LocalDate> learnedDates = logs.stream()
                .filter(log -> log.getInitialAt() != null)
                .map(log -> log.getInitialAt().toLocalDate())
                .collect(Collectors.toSet());

        List<Boolean> weeklyLog = new ArrayList<>();
        for (int i = 0; i < 7; i++) {
            LocalDate date = monday.plusDays(i);
            weeklyLog.add(learnedDates.contains(date));
        }
        return weeklyLog;
    }
}
