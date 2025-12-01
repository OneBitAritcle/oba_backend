package oba.backend.server.domain.quiz;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface IncorrectArticlesRepository extends JpaRepository<IncorrectArticles, IncorrectArticlesId> {

    List<IncorrectArticles> findByUserId(Long userId);

    void deleteByUserIdAndArticleId(Long userId, Long articleId);
}
