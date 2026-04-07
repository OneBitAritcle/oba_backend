package oba.backend.server.domain.ai.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import oba.backend.server.domain.ai.service.AiService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/ai")
@RequiredArgsConstructor
public class AiController {

    private final AiService aiService;

    @Value("${ai.internal-key:}")
    private String internalKey;

    @PostMapping("/generate/daily")
    public ResponseEntity<String> runDailyAi(
            @RequestHeader(value = "X-Internal-Key", required = false) String requestKey) {

        if (internalKey != null && !internalKey.isBlank()) {
            if (requestKey == null || !requestKey.equals(internalKey)) {
                log.warn("[AiController] 인증되지 않은 AI 엔드포인트 접근 시도");
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body("접근 권한이 없습니다.");
            }
        }

        String result = aiService.runDailyGptTask();
        return ResponseEntity.ok(result);
    }
}
