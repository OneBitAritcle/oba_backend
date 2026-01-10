package oba.backend.server.domain.quiz.service;

import lombok.RequiredArgsConstructor;
import oba.backend.server.global.auth.jwt.JwtProvider;
import oba.backend.server.domain.quiz.entity.IncorrectQuiz;
import oba.backend.server.domain.quiz.dto.QuizSubmitRequest;
import oba.backend.server.domain.quiz.repository.IncorrectQuizRepository;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class QuizService {

    private final IncorrectQuizRepository incorrectQuizRepository;
    private final JwtProvider jwtProvider;

    public void submit(String jwt, QuizSubmitRequest request) {
        Long userId = jwtProvider.getUserId(jwt);

        IncorrectQuiz incorrectQuiz = IncorrectQuiz.builder()
                .userId(userId)
                .articleId(request.getArticleId())
                .quiz1(request.getAnswers().get(0) == 1)
                .quiz2(request.getAnswers().get(1) == 1)
                .quiz3(request.getAnswers().get(2) == 1)
                .quiz4(request.getAnswers().get(3) == 1)
                .quiz5(request.getAnswers().get(4) == 1)
                .build();

        incorrectQuizRepository.save(incorrectQuiz);
    }
}
