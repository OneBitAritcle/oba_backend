package oba.backend.server.service;

import lombok.RequiredArgsConstructor;
import oba.backend.server.entity.mongo.GptDocument;
import oba.backend.server.entity.mysql.Article;
import oba.backend.server.entity.mysql.ArticleCategory;
import oba.backend.server.repository.mongo.GptMongoRepository;
import oba.backend.server.repository.mysql.ArticleCategoryRepository;
import oba.backend.server.repository.mysql.ArticleRepository;
import oba.backend.server.repository.mysql.CategoryRepository;
import oba.backend.server.dto.ArticleDetailResponse;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class ArticleDetailService {

    private final ArticleRepository articleRepository;
    private final CategoryRepository categoryRepository;
    private final ArticleCategoryRepository articleCategoryRepository;
    private final GptMongoRepository gptMongoRepository;

    public ArticleDetailResponse getArticleDetail(Long articleId) {

        Article article = articleRepository.findById(articleId)
                .orElseThrow(() -> new RuntimeException("Article not found"));

        List<ArticleCategory> mapping = articleCategoryRepository.findByIdArticleId(articleId);

        List<String> categories = mapping.stream()
                .map(m -> categoryRepository.findById(m.getId().getCategoryId()).get().getCategoryName())
                .toList();

        GptDocument doc = gptMongoRepository.findByArticleId(articleId)
                .orElseThrow(() -> new RuntimeException("GPT Result not found"));

        return ArticleDetailResponse.of(article, categories, doc);
    }
}
