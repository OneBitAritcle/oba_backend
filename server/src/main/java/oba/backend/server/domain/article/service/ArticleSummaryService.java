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
import java.util.Collections;
import java.util.List;

@Service
@RequiredArgsConstructor
public class ArticleSummaryService {

    private final GptMongoRepository gptMongoRepository;

    @Cacheable(value = Const.CACHE_LATEST_ARTICLES, key = "#limit")
    @Transactional(readOnly = true)
    public List<ArticleSummaryResponse> getLatestArticles(int limit) {
        // MongoDB에서 servingDate 기준 내림차순 조회
        List<GptDocument> docs = gptMongoRepository.findByOrderByServingDateDesc(PageRequest.of(0, limit));

        return docs.stream()
                .map(this::mapToSummary)
                .toList();
    }

    private ArticleSummaryResponse mapToSummary(GptDocument doc) {
        List<String> bullets = Collections.emptyList();

        // Entity의 getSummary() 편의 메서드 활용
        String summaryText = doc.getSummary();

        if (summaryText != null && !summaryText.isBlank()) {
            // 마침표(.), 가운데점(·), 줄바꿈(\n) 기준으로 문장 분리
            bullets = Arrays.stream(summaryText.split("[.·\\n]"))
                    .map(String::trim)
                    .filter(s -> !s.isBlank())
                    .limit(3) // 최대 3문장만 요약으로 표시
                    .toList();
        }

        return ArticleSummaryResponse.builder()
                .articleId(doc.getId())
                .title(doc.getTitle())
                .summaryBullets(bullets)
                .servingDate(doc.getServingDate())
                .build();
    }
}