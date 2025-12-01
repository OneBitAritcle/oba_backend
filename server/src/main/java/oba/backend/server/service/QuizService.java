package oba.backend.server.service;

import lombok.RequiredArgsConstructor;
import oba.backend.server.common.jwt.JwtProvider;
import oba.backend.server.domain.quiz.*;
import oba.backend.server.dto.QuizSubmitRequest;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class QuizService {

    private final JwtProvider jwtProvider;
    private final IncorrectArticlesRepository incorrectArticlesRepository;
    private final IncorrectQuizRepository incorrectQuizRepository;

    public void submitQuiz(String token, QuizSubmitRequest request) {

        Long userId = Long.valueOf(jwtProvider.getUserId(token));
        Long articleId = request.getArticleId();

        // 🔵 1) solved(푼 문제) 저장 — Incorrect_Articles
        IncorrectArticles solved = IncorrectArticles.builder()
                .userId(userId)
                .articleId(articleId)
                .solDate(LocalDateTime.now())
                .build();

        incorrectArticlesRepository.save(solved);


        // 🔵 2) 정오답 기록 저장 — Incorrect_Quiz
        IncorrectQuiz quiz = IncorrectQuiz.builder()
                .userId(userId)
                .articleId(articleId)
                .quiz1(request.getAnswers().get(0))
                .quiz2(request.getAnswers().get(1))
                .quiz3(request.getAnswers().get(2))
                .quiz4(request.getAnswers().get(3))
                .quiz5(request.getAnswers().get(4))
                .build();

        incorrectQuizRepository.save(quiz);
    }
}
