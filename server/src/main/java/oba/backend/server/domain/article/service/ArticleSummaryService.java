package oba.backend.server.domain.article.service;

import lombok.RequiredArgsConstructor;

import oba.backend.server.domain.article.dto.ArticleSummaryResponse;
import oba.backend.server.domain.article.entity.GptDocument;
import oba.backend.server.domain.article.repository.GptMongoRepository;
import oba.backend.server.global.common.Const;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.List;
import java.util.Collections;

@Service
@RequiredArgsConstructor
public class ArticleSummaryService {

    private final GptMongoRepository gptMongoRepository;

    @Cacheable(value = Const.CACHE_LATEST_ARTICLES, key = "#limit")
    @Transactional(readOnly = true)
    public List<ArticleSummaryResponse> getLatestArticles(int limit) {
        List<GptDocument> docs = gptMongoRepository.findByOrderByServingDateDesc(PageRequest.of(0, limit));

        return docs.stream().map(this::mapToSummary).toList();
    }

    private ArticleSummaryResponse mapToSummary(GptDocument doc) {
        List<String> bullets = Collections.emptyList();
        if (doc.getSummary() != null && !doc.getSummary().isBlank()) {
            bullets = Arrays.stream(doc.getSummary().split("[\\.|·|\\n]"))
                    .map(String::trim)
                    .filter(s -> !s.isBlank())
                    .limit(3)
                    .toList();
        }

        return ArticleSummaryResponse.builder()
                .articleId(doc.getArticleId())
                .title(doc.getTitle())
                .summaryBullets(bullets)
                .servingDate(doc.getServingDate())
                .build();
    }
}