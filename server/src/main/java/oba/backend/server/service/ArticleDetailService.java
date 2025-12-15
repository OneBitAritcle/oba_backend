package oba.backend.server.service;

import lombok.RequiredArgsConstructor;
import oba.backend.server.dto.ArticleDetailResponse;
import oba.backend.server.entity.mongo.GptDocument;
import oba.backend.server.repository.mongo.GptMongoRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class ArticleDetailService {

    private final GptMongoRepository gptMongoRepository;

    public ArticleDetailResponse getArticleDetail(Long articleId) {

        GptDocument doc = gptMongoRepository.findByArticleId(articleId)
                .orElseThrow(() -> new RuntimeException("Article not found"));

        // Keyword: List<Keyword> → List<String>
        List<String> keywordList = null;
        if (doc.getKeywords() != null) {
            keywordList = doc.getKeywords().stream()
                    .map(k -> k.getKeyword())
                    .toList();
        }

        // Quiz: List<Quiz> → List<Map<String,Object>>
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
                .content(doc.getContent())     // 원본 구조 그대로 내려줌
                .subtitle(doc.getSubtitle())
                .summary(doc.getSummary())
                .keywords(keywordList)
                .quizzes(quizList)
                .build();
    }
}
