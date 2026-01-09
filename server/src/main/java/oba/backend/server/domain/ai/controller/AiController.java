package oba.backend.server.controller;

import lombok.RequiredArgsConstructor;
import oba.backend.server.service.AiService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/ai")
@RequiredArgsConstructor
public class AiController {

    private final AiService aiService;

    @PostMapping("/generate/daily")
    public ResponseEntity<String> runDailyAi() {
        String result = aiService.runDailyGptTask();
        return ResponseEntity.ok(result);
    }
}
