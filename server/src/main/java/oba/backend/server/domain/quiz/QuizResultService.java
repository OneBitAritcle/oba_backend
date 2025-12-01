package oba.backend.server.domain.quiz;

import lombok.RequiredArgsConstructor;
import oba.backend.server.common.jwt.JwtProvider;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class QuizResultService {

    private final JwtProvider jwtProvider;
    private final IncorrectQuizRepository incorrectQuizRepository;
    private final IncorrectArticlesRepository incorrectArticlesRepository;

    @Transactional
    public void saveQuizResult(String jwt, QuizResultRequest request) {

        Long userId = Long.parseLong(jwtProvider.getUserId(jwt));
        boolean[] results = request.getQuizResults();

        // 기존 기록 제거
        incorrectQuizRepository.deleteByUserIdAndArticleId(userId, request.getArticleId());

        IncorrectQuiz quiz = IncorrectQuiz.builder()
                .userId(userId)
                .articleId(request.getArticleId())
                .quiz1(results.length > 0 ? results[0] : null)
                .quiz2(results.length > 1 ? results[1] : null)
                .quiz3(results.length > 2 ? results[2] : null)
                .quiz4(results.length > 3 ? results[3] : null)
                .quiz5(results.length > 4 ? results[4] : null)
                .build();

        incorrectQuizRepository.save(quiz);

        // 오답 기사 저장
        boolean hasWrong = false;
        for (boolean r : results) {
            if (!r) {
                hasWrong = true;
                break;
            }
        }

        if (hasWrong) {
            incorrectArticlesRepository.deleteByUserIdAndArticleId(userId, request.getArticleId());

            IncorrectArticles article = IncorrectArticles.builder()
                    .userId(userId)
                    .articleId(request.getArticleId())
                    .build();

            incorrectArticlesRepository.save(article);
        }
    }
}
