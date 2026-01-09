package oba.backend.server.domain.quiz.service;

import lombok.RequiredArgsConstructor;
import oba.backend.server.global.auth.jwt.JwtProvider;
import oba.backend.server.domain.quiz.dto.QuizResultRequest;
import oba.backend.server.domain.quiz.entity.IncorrectArticles;
import oba.backend.server.domain.quiz.repository.IncorrectArticlesRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class QuizResultService {

    private final IncorrectArticlesRepository incorrectArticlesRepository;
    private final JwtProvider jwtProvider;

    public void saveQuizResult(String jwt, QuizResultRequest request) {
        Long userId = jwtProvider.getUserId(jwt);

        IncorrectArticles incorrectArticles = IncorrectArticles.builder()
                .userId(userId)
                .articleId(request.getArticleId())
                .solDate(LocalDateTime.now())
                .build();

        incorrectArticlesRepository.save(incorrectArticles);
    }
}
