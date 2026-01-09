package oba.backend.server.domain.article.repository;

import oba.backend.server.domain.article.entity.GptDocument;
import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;
import java.util.Optional;

public interface GptMongoRepository extends MongoRepository<GptDocument, String> {

    Optional<GptDocument> findByArticleId(Long articleId);

    List<GptDocument> findByOrderByServingDateDesc(Pageable pageable);
}
