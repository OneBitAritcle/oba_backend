package oba.backend.server.domain.article.service;

import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.article.dto.ArticleDetailResponse;
import oba.backend.server.domain.article.entity.SelectedArticle;
import oba.backend.server.domain.article.repository.GptMongoRepository;
import oba.backend.server.domain.quiz.entity.IncorrectQuiz;
import oba.backend.server.domain.quiz.repository.IncorrectQuizRepository;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ArticleDetailService {

    private final GptMongoRepository gptMongoRepository;
    private final IncorrectQuizRepository incorrectQuizRepository;

    public ArticleDetailResponse getArticleDetail(String articleId, Long userId) {
        // Mongo에서 기사 조회
        SelectedArticle doc = gptMongoRepository.findById(articleId)
                .orElseThrow(() -> new IllegalArgumentException("해당 ID의 기사를 찾을 수 없습니다: " + articleId));

        List<Boolean> myResults = Collections.emptyList();

        if (userId != null) {
            Long numericId = doc.getArticleId();
            if (numericId != null) {
                Optional<IncorrectQuiz> quizRecord = incorrectQuizRepository.findByUserIdAndArticleId(userId, numericId);
                if (quizRecord.isPresent()) {
                    myResults = quizRecord.get().getQuizResults();
                }
            }
        }

        List<ArticleDetailResponse.KeywordDto> keywordDtos = doc.getKeywordItems().stream()
                .map(item -> ArticleDetailResponse.KeywordDto.builder()
                        .keyword(item.getKeyword())
                        .description(item.getDescription()) // 설명 필드 매핑
                        .build())
                .collect(Collectors.toList());

        return ArticleDetailResponse.builder()
                .articleId(doc.getId())
                .title(doc.getTitle())
                .content(doc.getContent())
                .summaryBullets(doc.getSummaryBullets())
                .keywords(keywordDtos)
                .servingDate(doc.getServingDate())
                .quizzes(doc.getQuizzes())
                .myQuizResults(myResults)
                .build();
    }
}