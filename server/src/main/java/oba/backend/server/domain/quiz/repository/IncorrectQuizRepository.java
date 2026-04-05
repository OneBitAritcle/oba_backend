package oba.backend.server.domain.quiz.repository;

import oba.backend.server.domain.quiz.entity.IncorrectQuiz;
import oba.backend.server.domain.log.entity.ArticleLogId;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;

public interface IncorrectQuizRepository extends JpaRepository<IncorrectQuiz, ArticleLogId> {
    List<IncorrectQuiz> findByUserId(Long userId);
    Optional<IncorrectQuiz> findByUserIdAndArticleId(Long userId, Long articleId);
}