package oba.backend.server.domain.quiz;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface IncorrectQuizRepository extends JpaRepository<IncorrectQuiz, IncorrectQuizId> {

    List<IncorrectQuiz> findByUserId(Long userId);

    void deleteByUserIdAndArticleId(Long userId, Long articleId);
}
