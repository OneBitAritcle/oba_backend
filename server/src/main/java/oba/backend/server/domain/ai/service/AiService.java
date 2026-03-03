package oba.backend.server.domain.ai.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
@RequiredArgsConstructor
public class AiService {

    private final RestTemplate restTemplate;

    @Value("${ai.server.url:http://ai_service:8000/generate/daily_gpt_results}")
    private String fastApiUrl;

    public String runDailyGptTask() {
        ResponseEntity<String> response =
                restTemplate.postForEntity(fastApiUrl, null, String.class);
        return response.getBody();
    }
}
