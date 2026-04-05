package oba.backend.server.domain.quiz.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import oba.backend.server.domain.article.entity.SelectedArticle;
import oba.backend.server.domain.article.repository.GptMongoRepository;
import oba.backend.server.domain.quiz.dto.QuizSubmitRequest;
import oba.backend.server.domain.quiz.entity.IncorrectQuiz;
import oba.backend.server.domain.quiz.repository.IncorrectQuizRepository;
import oba.backend.server.global.auth.jwt.JwtProvider;
import oba.backend.server.global.exception.BusinessException;
import oba.backend.server.global.exception.ErrorCode;
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

        SelectedArticle article = gptMongoRepository.findById(request.getArticleId())
                .orElseThrow(() -> new BusinessException(ErrorCode.ARTICLE_NOT_FOUND));

        Long numericArticleId = article.getArticleId();
        if (numericArticleId == null) {
            throw new BusinessException(ErrorCode.ARTICLE_NOT_FOUND, "기사의 숫자 ID가 없습니다.");
        }

        List<Integer> userAnswers = request.getAnswers();
        List<SelectedArticle.QuizItem> quizzes = article.getQuizzes();

        if (quizzes == null || userAnswers.size() != quizzes.size()) {
            throw new BusinessException(ErrorCode.QUIZ_RESULT_MISMATCH);
        }

        List<Boolean> results = new ArrayList<>();
        for (int i = 0; i < quizzes.size(); i++) {
            int userIndex = userAnswers.get(i);
            int correctIndex = quizzes.get(i).getAnswerIndex();
            results.add(userIndex == correctIndex);
        }

        IncorrectQuiz incorrectQuiz = IncorrectQuiz.builder()
                .userId(userId)
                .articleId(numericArticleId)
                .build();

        incorrectQuiz.setQuizResults(results);
        incorrectQuizRepository.save(incorrectQuiz);
    }
}
