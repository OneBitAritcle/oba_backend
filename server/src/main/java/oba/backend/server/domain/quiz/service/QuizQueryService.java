package oba.backend.server.domain.quiz.service;

import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.article.entity.SelectedArticle;
import oba.backend.server.domain.article.repository.GptMongoRepository;
import oba.backend.server.domain.quiz.dto.SolvedArticleResponse;
import oba.backend.server.domain.quiz.dto.WrongArticleResponse;
import oba.backend.server.domain.quiz.entity.IncorrectQuiz;
import oba.backend.server.domain.quiz.repository.IncorrectQuizRepository;
import oba.backend.server.global.auth.jwt.JwtProvider;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class QuizQueryService {

    private final IncorrectQuizRepository incorrectQuizRepository;
    private final GptMongoRepository gptMongoRepository;
    private final JwtProvider jwtProvider;

    // 1. 내가 푼 문제 (SQL Long ID -> Mongo 조회 -> String ID 반환)
    public List<SolvedArticleResponse> getSolved(Long userId) {
        return incorrectQuizRepository.findByUserId(userId).stream() // findAllByUserId -> findByUserId
                .map(record -> {
                    // Long ID로 Mongo 문서 찾기
                    SelectedArticle article = gptMongoRepository.findByArticleId(record.getArticleId())
                            .orElse(null);

                    String title = (article != null) ? article.getTitle() : "삭제된 기사";
                    String mongoId = (article != null) ? article.getId() : "";

                    return SolvedArticleResponse.builder()
                            .articleId(mongoId) // 프론트엔드용 String ID 반환
                            .title(title)
                            .solvedAt(LocalDate.now().toString())
                            .build();
                })
                .collect(Collectors.toList());
    }

    // 2. 오답 노트
    public List<WrongArticleResponse> getWrong(Long userId) {
        List<IncorrectQuiz> records = incorrectQuizRepository.findByUserId(userId);
        List<WrongArticleResponse> responseList = new ArrayList<>();

        for (IncorrectQuiz record : records) {
            // 오답이 하나라도 있으면
            if (record.getQuizResults().contains(false)) {
                // Long ID -> Mongo Document
                SelectedArticle article = gptMongoRepository.findByArticleId(record.getArticleId())
                        .orElse(null);

                if (article != null) {
                    String summary = (article.getSummaryBullets() != null && !article.getSummaryBullets().isEmpty())
                            ? article.getSummaryBullets().get(0) : "요약 없음";

                    responseList.add(WrongArticleResponse.builder()
                            .articleId(article.getId()) // Mongo ID (String)
                            .title(article.getTitle())
                            .summary(summary)
                            .category("Tech")
                            .solvedAt(LocalDate.now().toString())
                            .build());
                }
            }
        }
        return responseList;
    }

    public List<Boolean> getWeeklyLog(Long userId) {
        // 임시 더미 데이터 (UserStats와 연동 필요)
        List<Boolean> weeklyLog = new ArrayList<>();
        for (int i = 0; i < 7; i++) weeklyLog.add(false);
        return weeklyLog;
    }
}