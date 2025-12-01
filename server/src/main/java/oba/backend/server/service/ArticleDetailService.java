package oba.backend.server.service;

import lombok.RequiredArgsConstructor;
import oba.backend.server.dto.ArticleDetailResponse;
import oba.backend.server.entity.mongo.GptDocument;
import oba.backend.server.repository.mongo.GptMongoRepository;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ArticleDetailService {

    private final GptMongoRepository gptMongoRepository;

    public ArticleDetailResponse getArticleDetail(Long articleId) {

        GptDocument doc = gptMongoRepository.findByArticleId(articleId)
                .orElseThrow(() -> new RuntimeException("Article not found"));

        return ArticleDetailResponse.builder()
                .articleId(doc.getArticleId())
                .title(doc.getTitle())
                .publishTime(doc.getPublishTime())
                .servingDate(doc.getServingDate())
                .content(doc.getContent())
                .subtitle(doc.getSubtitle())
                .summary(doc.getSummary())
                .keywords(doc.getKeywords())
                .quizzes(doc.getQuizzes())
                .build();
    }
}
