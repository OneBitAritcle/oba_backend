package oba.backend.server.doma.article.service;

import lombok.RequiredArgsConstructor;
import oba.backend.server.doma.article.dto.ArticleSummaryResponse;
import oba.backend.server.doma.article.entity.GptDocument;
import oba.backend.server.doma.article.repository.GptMongoRepository;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

@Service
@RequiredArgsConstructor
public class ArticleSummaryService {

    private final GptMongoRepository gptMongoRepository;

    @Cacheable(value = "latestArticles", key = "#limit", unless = "#result == null || #result.isEmpty()")
    public List<ArticleSummaryResponse> getLatestArticles(int limit) {

        Pageable pageable = PageRequest.of(0, limit);
        List<GptDocument> docs = gptMongoRepository.findByOrderByServingDateDesc(pageable);

        return docs.stream().map(doc -> {
            List<String> bullets = null;

            if (doc.getSummary() != null) {
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

        }).toList();
    }
}
