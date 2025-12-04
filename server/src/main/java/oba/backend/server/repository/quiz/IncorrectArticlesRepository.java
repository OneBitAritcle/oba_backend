package oba.backend.server.repository.mysql;

import oba.backend.server.domain.quiz.IncorrectArticles;
import oba.backend.server.domain.quiz.IncorrectArticlesId;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface IncorrectArticlesRepository
        extends JpaRepository<IncorrectArticles, IncorrectArticlesId> {

    List<IncorrectArticles> findByUserId(Long userId);

    void deleteByUserIdAndArticleId(Long userId, Long articleId);
}
