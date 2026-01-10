package oba.backend.server.domain.article.service;

import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.article.dto.ArticleDetailResponse;
import oba.backend.server.domain.article.entity.GptDocument;
import oba.backend.server.domain.article.repository.GptMongoRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.List;

@Service
@RequiredArgsConstructor
public class ArticleDetailService {

    private final GptMongoRepository gptMongoRepository;

    // 🚨 수정됨: 인자 타입 Long -> String
    @Transactional(readOnly = true)
    public ArticleDetailResponse getArticleDetail(String id) {

        // MongoDB _id(String)로 조회
        GptDocument doc = gptMongoRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("해당 ID의 기사를 찾을 수 없습니다: " + id));

        // 키워드 리스트 매핑
        List<String> keywordList = Collections.emptyList();
        if (doc.getKeywords() != null) {
            keywordList = doc.getKeywords().stream()
                    .map(GptDocument.GptResult.Keyword::getKeyword)
                    .toList();
        }

        // 퀴즈 리스트 매핑
        List<ArticleDetailResponse.QuizDto> quizList = Collections.emptyList();
        if (doc.getQuizzes() != null) {
            quizList = doc.getQuizzes().stream()
                    .map(q -> ArticleDetailResponse.QuizDto.builder()
                            .question(q.getQuestion())
                            .options(q.getOptions())
                            .answer(parseAnswerIndex(q.getAnswer(), q.getOptions())) // 정답 인덱스 변환 로직
                            .explanation(q.getExplanation())
                            .build())
                    .toList();
        }

        return ArticleDetailResponse.builder()
                .articleId(doc.getId()) // String ID 사용
                .title(doc.getTitle())
                .publishTime(doc.getPublishTime())
                .servingDate(doc.getServingDate())
                .content(doc.getContent()) // List<Object>
                .subtitle(doc.getSubtitle()) // List<String>
                .summary(doc.getSummary())
                .keywords(keywordList)
                .quizzes(quizList)
                .build();
    }

    // GPT가 정답을 "1" 같은 문자열이나 텍스트로 줄 수 있으므로 인덱스(int)로 변환하는 헬퍼 메서드
    private int parseAnswerIndex(String answerStr, List<String> options) {
        try {
            // 1. 숫자만 있는 경우 ("0", "1" 등)
            if (answerStr.matches("\\d+")) {
                return Integer.parseInt(answerStr);
            }
            // 2. 정답 텍스트 자체가 들어있는 경우 -> 보기 리스트에서 찾기
            int idx = options.indexOf(answerStr);
            if (idx != -1) return idx;

            return 0; // 기본값 (에러 방지)
        } catch (Exception e) {
            return 0;
        }
    }
}