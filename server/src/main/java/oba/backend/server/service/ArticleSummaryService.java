package oba.backend.server.service;

import lombok.RequiredArgsConstructor;
import oba.backend.server.dto.ArticleSummaryResponse;
import oba.backend.server.entity.mongo.GptDocument;
import oba.backend.server.repository.mongo.GptMongoRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

@Service
@RequiredArgsConstructor
public class ArticleSummaryService {

    private final GptMongoRepository gptMongoRepository;

    public List<ArticleSummaryResponse> getLatestArticles(int limit) {

        Pageable pageable = PageRequest.of(0, limit);
        List<GptDocument> docs = gptMongoRepository.findByOrderByServingDateDesc(pageable);

        return docs.stream().map(doc -> {

            List<String> bullets = null;
            if (doc.getSummary() != null) {
                bullets = Arrays.stream(doc.getSummary().split(" "))
                        .limit(3)
                        .toList();
            }

            return ArticleSummaryResponse.builder()
                    .articleId(doc.getArticleId())
                    .title(doc.getTitle())
                    .summaryBullets(bullets)
                    .servingDate(doc.getServingDate()) // String OK
                    .build();

        }).toList();
    }
}
