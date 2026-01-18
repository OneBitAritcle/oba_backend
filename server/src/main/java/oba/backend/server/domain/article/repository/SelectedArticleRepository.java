package oba.backend.server.domain.article.repository;

import oba.backend.server.domain.article.entity.SelectedArticle;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface SelectedArticleRepository
        extends MongoRepository<SelectedArticle, String> {
}
