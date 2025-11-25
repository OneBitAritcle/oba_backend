package oba.backend.server.service;

import lombok.RequiredArgsConstructor;
import oba.backend.server.repository.mongo.GptMongoRepository;
import oba.backend.server.repository.mysql.ArticleRepository;
import oba.backend.server.dto.ArticleSummaryResponse;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Service
@RequiredArgsConstructor
public class ArticleSummaryService {

    private final ArticleRepository articleRepository;
    private final GptMongoRepository gptMongoRepository;

    public List<ArticleSummaryResponse> getLatestArticles(int limit) {

        var latest = articleRepository.findLatestArticles(PageRequest.of(0, limit));

        return latest.stream().map(a -> {

            oba.backend.server.entity.mongo.GptDocument doc = gptMongoRepository.findByArticleId(a.getArticleId())
                    .orElse(null);

            List<String> bullets = new ArrayList<>();

            if (doc != null && doc.getGptResult() != null) {
                String s = doc.getGptResult().getSummary();
                if (s != null) {
                    bullets = Arrays.stream(s.split(" "))
                            .limit(5)
                            .toList();
                }
            }

            return ArticleSummaryResponse.builder()
                    .id(a.getArticleId())
                    .title(doc != null ? doc.getTitle() : "(제목 없음)")
                    .bullets(bullets)
                    .build();
        }).toList();
    }
}
