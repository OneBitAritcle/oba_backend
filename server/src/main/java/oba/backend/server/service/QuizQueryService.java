package oba.backend.server.service;

import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.quiz.IncorrectArticlesRepository;
import oba.backend.server.domain.quiz.IncorrectQuizRepository;
import oba.backend.server.domain.quiz.dto.SolvedArticleResponse;
import oba.backend.server.domain.quiz.dto.WrongArticleResponse;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class QuizQueryService {

    private final IncorrectArticlesRepository incorrectArticlesRepository;
    private final IncorrectQuizRepository incorrectQuizRepository;

    public List<SolvedArticleResponse> getSolved(Long userId) {
        return incorrectArticlesRepository.findByUserId(userId)
                .stream()
                .map(r -> SolvedArticleResponse.builder()
                        .articleId(r.getArticleId())
                        .solvedAt(r.getSolDate())
                        .build())
                .collect(Collectors.toList());
    }

    public List<WrongArticleResponse> getWrong(Long userId) {
        return incorrectQuizRepository.findByUserId(userId)
                .stream()
                .map(q -> WrongArticleResponse.builder()
                        .articleId(q.getArticleId())
                        .wrongList(new boolean[]{
                                !q.getQuiz1(),
                                !q.getQuiz2(),
                                !q.getQuiz3(),
                                !q.getQuiz4(),
                                !q.getQuiz5()
                        })
                        .build())
                .collect(Collectors.toList());
    }
}
