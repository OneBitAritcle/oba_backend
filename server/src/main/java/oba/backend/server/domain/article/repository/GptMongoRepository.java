package oba.backend.server.domain.article.repository;

import oba.backend.server.domain.article.entity.SelectedArticle;
import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface GptMongoRepository extends MongoRepository<SelectedArticle, String> {
    List<SelectedArticle> findByOrderByServingDateDesc(Pageable pageable);

    List<SelectedArticle> findByServingDateOrderByPublishTimeAsc(String servingDate, Pageable pageable);

    // 숫자 ID로 기사 찾기 (SQL <-> Mongo 매핑용)
    Optional<SelectedArticle> findByArticleId(Long articleId);
}