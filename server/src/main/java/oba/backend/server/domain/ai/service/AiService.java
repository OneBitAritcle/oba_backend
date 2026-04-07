package oba.backend.server.domain.ai.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import oba.backend.server.global.exception.BusinessException;
import oba.backend.server.global.exception.ErrorCode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class AiService {

    private final RestTemplate restTemplate;

    @Value("${ai.server.url:http://ai_backend:8000}")
    private String aiServerUrl;

    public String runDailyGptTask() {
        String url = aiServerUrl + "/generate/daily_gpt_results";
        log.info("[AiService] 일괄 GPT 처리 요청 -> {}", url);

        try {
            ResponseEntity<String> response = restTemplate.postForEntity(url, null, String.class);
            return response.getBody();
        } catch (ResourceAccessException e) {
            log.error("[AiService] AI 서버 연결 실패: {}", e.getMessage());
            throw new BusinessException(ErrorCode.AI_SERVICE_ERROR, "AI 서버에 연결할 수 없습니다.");
        } catch (RestClientException e) {
            log.error("[AiService] AI 서버 요청 실패: {}", e.getMessage());
            throw new BusinessException(ErrorCode.AI_SERVICE_ERROR);
        }
    }

    public void processArticle(String mongoObjectId) {
        String url = aiServerUrl + "/generate/gpt_result";
        log.info("[AiService] 단일 기사 GPT 처리 요청 -> {} (id={})", url, mongoObjectId);

        try {
            Map<String, String> body = Map.of("article_id", mongoObjectId);
            ResponseEntity<String> response = restTemplate.postForEntity(url, body, String.class);
            log.info("[AiService] GPT 처리 완료: {}", response.getBody());
        } catch (ResourceAccessException e) {
            log.error("[AiService] AI 서버 연결 실패: {}", e.getMessage());
            throw new BusinessException(ErrorCode.AI_SERVICE_ERROR, "AI 서버에 연결할 수 없습니다.");
        } catch (RestClientException e) {
            log.error("[AiService] AI 서버 요청 실패: {}", e.getMessage());
            throw new BusinessException(ErrorCode.AI_SERVICE_ERROR);
        }
    }
}
