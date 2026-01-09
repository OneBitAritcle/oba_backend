package oba.backend.server.doma.article.service;

import lombok.RequiredArgsConstructor;
import oba.backend.server.doma.article.dto.ArticleDetailResponse;
import oba.backend.server.doma.article.entity.GptDocument;
import oba.backend.server.doma.article.repository.GptMongoRepository;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class ArticleDetailService {

    private final GptMongoRepository gptMongoRepository;

    @Cacheable(value = "articleDetail", key = "#articleId", unless = "#result == null")
    public ArticleDetailResponse getArticleDetail(Long articleId) {

        GptDocument doc = gptMongoRepository.findByArticleId(articleId)
                .orElseThrow(() -> new RuntimeException("Article not found: " + articleId));

        List<String> keywordList = null;
        if (doc.getKeywords() != null) {
            keywordList = doc.getKeywords().stream()
                    .map(GptDocument.GptResult.Keyword::getKeyword)
                    .toList();
        }

        List<Map<String, Object>> quizList = null;
        if (doc.getQuizzes() != null) {
            quizList = doc.getQuizzes().stream()
                    .map(q -> Map.of(
                            "question", q.getQuestion(),
                            "options", q.getOptions(),
                            "answer", QuizAnswerParser.toIndex(q.getAnswer()),
                            "explanation", q.getExplanation()
                    ))
                    .toList();
        }

        return ArticleDetailResponse.builder()
                .articleId(doc.getArticleId())
                .title(doc.getTitle())
                .publishTime(doc.getPublishTime())
                .servingDate(doc.getServingDate())
                .content(doc.getContent())
                .subtitle(doc.getSubtitle())
                .summary(doc.getSummary())
                .keywords(keywordList)
                .quizzes(quizList)
                .build();
    }
}
