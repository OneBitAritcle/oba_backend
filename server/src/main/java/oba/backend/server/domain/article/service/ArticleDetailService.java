package oba.backend.server.domain.article.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import oba.backend.server.domain.ai.service.AiService;
import oba.backend.server.domain.article.dto.ArticleDetailResponse;
import oba.backend.server.domain.article.entity.SelectedArticle;
import oba.backend.server.domain.article.repository.GptMongoRepository;
import oba.backend.server.domain.quiz.entity.IncorrectQuiz;
import oba.backend.server.domain.quiz.repository.IncorrectQuizRepository;
import oba.backend.server.global.exception.BusinessException;
import oba.backend.server.global.exception.ErrorCode;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class ArticleDetailService {

    private final GptMongoRepository gptMongoRepository;
    private final IncorrectQuizRepository incorrectQuizRepository;
    private final AiService aiService;

    public ArticleDetailResponse getArticleDetail(String articleId, Long userId) {
        SelectedArticle doc = gptMongoRepository.findById(articleId)
                .orElseThrow(() -> new BusinessException(ErrorCode.ARTICLE_NOT_FOUND));

        if (doc.getGptResult() == null) {
            log.info("[ArticleDetailService] gpt_result 없음 -> GPT 처리 요청 (articleId={})", articleId);
            try {
                aiService.processArticle(articleId);
                doc = gptMongoRepository.findById(articleId)
                        .orElseThrow(() -> new BusinessException(ErrorCode.ARTICLE_NOT_FOUND));
            } catch (BusinessException e) {
                log.warn("[ArticleDetailService] GPT 처리 실패, 원본 기사 반환: {}", e.getMessage());
            }
        }

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
                        .description(item.getDescription())
                        .build())
                .collect(Collectors.toList());

        return ArticleDetailResponse.builder()
                .articleId(doc.getId())
                .title(doc.getTitle())
                .categoryName(doc.getCategoryName())
                .content(doc.getContent())
                .summaryBullets(doc.getSummaryBullets())
                .keywords(keywordDtos)
                .servingDate(doc.getServingDate())
                .quizzes(doc.getQuizzes())
                .myQuizResults(myResults)
                .build();
    }
}
