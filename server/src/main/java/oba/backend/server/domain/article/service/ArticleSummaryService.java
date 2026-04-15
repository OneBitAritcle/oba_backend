package oba.backend.server.domain.article.service;

import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.article.dto.ArticleSummaryResponse;
import oba.backend.server.domain.article.entity.SelectedArticle;
import oba.backend.server.domain.article.repository.GptMongoRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ArticleSummaryService {

    private final GptMongoRepository gptMongoRepository;

    public List<ArticleSummaryResponse> getLatestArticles(int limit) {
        String today = LocalDate.now().toString();
        List<SelectedArticle> docs = gptMongoRepository
                .findByServingDateOrderByPublishTimeAsc(today, PageRequest.of(0, limit));

        return docs.stream()
                .map(doc -> ArticleSummaryResponse.builder()
                        .articleId(doc.getId())
                        .title(doc.getTitle())
                        .summaryBullets(doc.getSummaryBullets()) // 엔티티 메서드 사용
                        .servingDate(doc.getServingDate())     // 엔티티 Getter 사용
                        .build())
                .collect(Collectors.<ArticleSummaryResponse>toList());
    }
}