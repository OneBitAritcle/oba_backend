package oba.backend.server.domain.quiz.service;

import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.article.entity.SelectedArticle;
import oba.backend.server.domain.article.repository.GptMongoRepository;
import oba.backend.server.domain.log.entity.ArticleLog;
import oba.backend.server.domain.log.repository.ArticleLogRepository;
import oba.backend.server.domain.quiz.dto.QuizResultRequest;
import oba.backend.server.domain.quiz.entity.IncorrectQuiz;
import oba.backend.server.domain.quiz.repository.IncorrectQuizRepository;
import oba.backend.server.domain.user.entity.User;
import oba.backend.server.domain.user.repository.UserRepository;
import oba.backend.server.global.auth.jwt.JwtProvider;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class QuizResultService {

    private final JwtProvider jwtProvider;
    private final UserRepository userRepository;
    private final IncorrectQuizRepository incorrectQuizRepository;
    private final ArticleLogRepository articleLogRepository;
    private final GptMongoRepository gptMongoRepository;

    @Transactional
    public void saveQuizResult(String token, QuizResultRequest request) {
        Long userId = jwtProvider.getUserId(token);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("유저 없음"));
        user.updateStreak(); // UserStats 갱신

        // Mongo ID -> Numeric ID 변환
        SelectedArticle article = gptMongoRepository.findById(request.getArticleId())
                .orElseThrow(() -> new IllegalArgumentException("기사를 찾을 수 없습니다."));
        Long numericArticleId = article.getArticleId();

        // 학습 로그 (Article_Logs) 저장/갱신
        ArticleLog log = articleLogRepository.findById(new oba.backend.server.domain.log.entity.ArticleLogId(userId, numericArticleId))
                .orElseGet(() -> ArticleLog.builder()
                        .userId(userId)
                        .articleId(numericArticleId)
                        .build());

        // 정답 여부 체크 (모두 true일 때 해결 처리)
        if (!request.getResults().contains(false)) {
            log.markAsResolved();
        }
        articleLogRepository.save(log);

        // 오답 상세 (Incorrect_Quiz) 저장
        IncorrectQuiz quizRecord = incorrectQuizRepository
                .findByUserIdAndArticleId(userId, numericArticleId)
                .orElseGet(() -> IncorrectQuiz.builder()
                        .userId(userId)
                        .articleId(numericArticleId)
                        .build());

        quizRecord.setQuizResults(request.getResults());
        incorrectQuizRepository.save(quizRecord);
    }
}