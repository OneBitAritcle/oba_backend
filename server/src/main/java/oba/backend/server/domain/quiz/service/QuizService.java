package oba.backend.server.domain.quiz.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import oba.backend.server.domain.article.entity.SelectedArticle;
import oba.backend.server.domain.article.repository.GptMongoRepository;
import oba.backend.server.domain.quiz.dto.QuizSubmitRequest;
import oba.backend.server.domain.quiz.entity.IncorrectQuiz;
import oba.backend.server.domain.quiz.repository.IncorrectQuizRepository;
import oba.backend.server.global.auth.jwt.JwtProvider;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class QuizService {

    private final IncorrectQuizRepository incorrectQuizRepository;
    private final GptMongoRepository gptMongoRepository;
    private final JwtProvider jwtProvider;

    @Transactional
    public void submit(String jwt, QuizSubmitRequest request) {
        Long userId = jwtProvider.getUserId(jwt);

        // Mongo에서 기사 조회 (String ID 사용)
        SelectedArticle article = gptMongoRepository.findById(request.getArticleId())
                .orElseThrow(() -> new IllegalArgumentException("해당 기사 없음"));

        // 숫자 ID 추출 (MySQL 저장용)
        Long numericArticleId = article.getArticleId();
        if (numericArticleId == null) {
            throw new IllegalArgumentException("기사 ID(숫자)가 존재하지 않습니다.");
        }

        // 정답 판별
        List<Integer> userAnswers = request.getAnswers();
        List<SelectedArticle.QuizItem> quizzes = article.getQuizzes();

        if (userAnswers.size() != quizzes.size()) {
            throw new IllegalArgumentException("답변 수와 문제 수가 일치하지 않음");
        }

        List<Boolean> results = new ArrayList<>();
        for (int i = 0; i < quizzes.size(); i++) {
            int userIndex = userAnswers.get(i);
            int correctIndex = quizzes.get(i).getAnswerIndex();
            boolean isCorrect = (userIndex == correctIndex);
            results.add(isCorrect);
        }

        // 저장 (Long ID 사용)
        IncorrectQuiz incorrectQuiz = IncorrectQuiz.builder()
                .userId(userId)
                .articleId(numericArticleId)
                .build();

        // Helper 메서드로 결과 주입
        incorrectQuiz.setQuizResults(results);

        incorrectQuizRepository.save(incorrectQuiz);
    }
}