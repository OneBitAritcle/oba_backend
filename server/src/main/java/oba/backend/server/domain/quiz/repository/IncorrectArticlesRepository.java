package oba.backend.server.domain.quiz.repository;

import oba.backend.server.domain.quiz.entity.IncorrectArticles;
import oba.backend.server.domain.quiz.entity.IncorrectArticlesId;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface IncorrectArticlesRepository extends JpaRepository<IncorrectArticles, IncorrectArticlesId> {

    List<IncorrectArticles> findByUserId(Long userId);

    void deleteByUserIdAndArticleId(Long userId, Long articleId);
}
