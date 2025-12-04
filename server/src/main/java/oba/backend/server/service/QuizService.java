package oba.backend.server.service;

import lombok.RequiredArgsConstructor;
import oba.backend.server.common.jwt.JwtProvider;
import oba.backend.server.domain.quiz.IncorrectQuiz;
import oba.backend.server.dto.QuizSubmitRequest;
import oba.backend.server.repository.quiz.IncorrectQuizRepository;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class QuizService {

    private final IncorrectQuizRepository incorrectQuizRepository;
    private final JwtProvider jwtProvider;

    public void submit(String jwt, QuizSubmitRequest request) {

        // 1) JWT → userId 추출
        Long userId = jwtProvider.getUserId(jwt);

        // 2) Entity 생성
        IncorrectQuiz incorrectQuiz = IncorrectQuiz.builder()
                .userId(userId)
                .articleId(request.getArticleId())
                .quiz1(request.getAnswers().get(0) == 1)
                .quiz2(request.getAnswers().get(1) == 1)
                .quiz3(request.getAnswers().get(2) == 1)
                .quiz4(request.getAnswers().get(3) == 1)
                .quiz5(request.getAnswers().get(4) == 1)
                .build();

        // 3) 저장
        incorrectQuizRepository.save(incorrectQuiz);
    }
}
