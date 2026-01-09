package oba.backend.server.doma.quiz.repository;

import oba.backend.server.doma.quiz.entity.IncorrectQuiz;
import oba.backend.server.doma.quiz.entity.IncorrectQuizId;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface IncorrectQuizRepository extends JpaRepository<IncorrectQuiz, IncorrectQuizId> {

    List<IncorrectQuiz> findByUserId(Long userId);

    void deleteByUserIdAndArticleId(Long userId, Long articleId);
}
