package oba.backend.server.service;

import lombok.RequiredArgsConstructor;
import oba.backend.server.dto.SolvedArticleResponse;
import oba.backend.server.dto.WrongArticleResponse;
import oba.backend.server.repository.quiz.IncorrectArticlesRepository;
import oba.backend.server.repository.quiz.IncorrectQuizRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class QuizQueryService {

    private final IncorrectArticlesRepository incorrectArticlesRepository;
    private final IncorrectQuizRepository incorrectQuizRepository;

    /** 사용자가 맞힌 기사 리스트 */
    public List<SolvedArticleResponse> getSolved(Long userId) {

        return incorrectArticlesRepository.findByUserId(userId)
                .stream()
                .map(a -> SolvedArticleResponse.builder()
                        .articleId(a.getArticleId())
                        .solvedAt(a.getSolDate().toString())
                        .build())
                .collect(Collectors.toList());
    }

    /** 사용자가 틀린 문제 리스트 */
    public List<WrongArticleResponse> getWrong(Long userId) {

        return incorrectQuizRepository.findByUserId(userId)
                .stream()
                .map(q -> WrongArticleResponse.builder()
                        .articleId(q.getArticleId())
                        .incorrectAnswers(
                                new boolean[]{
                                        q.isQuiz1(),
                                        q.isQuiz2(),
                                        q.isQuiz3(),
                                        q.isQuiz4(),
                                        q.isQuiz5()
                                }
                        ).build())
                .collect(Collectors.toList());
    }
}
