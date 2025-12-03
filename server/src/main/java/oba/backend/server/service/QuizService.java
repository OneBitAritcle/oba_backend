package oba.backend.server.service;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import oba.backend.server.common.jwt.JwtProvider;
import oba.backend.server.domain.quiz.IncorrectArticles;
import oba.backend.server.domain.quiz.IncorrectArticlesRepository;
import oba.backend.server.domain.quiz.IncorrectQuiz;
import oba.backend.server.domain.quiz.IncorrectQuizRepository;
import oba.backend.server.domain.user.User;
import oba.backend.server.domain.user.UserRepository;
import oba.backend.server.dto.QuizSubmitRequest;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class QuizService {

    private final JwtProvider jwtProvider;
    private final UserRepository userRepository;
    private final IncorrectArticlesRepository incorrectArticlesRepository;
    private final IncorrectQuizRepository incorrectQuizRepository;

    public void submit(String jwt, QuizSubmitRequest request) {

        // 🔥 JWT subject = identifier
        Claims claims = jwtProvider.getClaims(jwt);
        String identifier = claims.getSubject();

        User user = userRepository.findByIdentifier(identifier)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Long userId = user.getId();
        Long articleId = request.getArticleId();

        // 🔵 solved 저장
        IncorrectArticles solved = IncorrectArticles.builder()
                .userId(userId)
                .articleId(articleId)
                .solDate(LocalDateTime.now())
                .build();

        incorrectArticlesRepository.save(solved);

        // 🔵 정오답 저장
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
