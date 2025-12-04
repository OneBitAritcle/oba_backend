package oba.backend.server.service;

import lombok.RequiredArgsConstructor;
import oba.backend.server.common.jwt.JwtProvider;
import oba.backend.server.dto.QuizResultRequest;
import oba.backend.server.domain.quiz.IncorrectArticles;
import oba.backend.server.domain.quiz.IncorrectArticlesId;
import oba.backend.server.repository.quiz.IncorrectArticlesRepository;
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

