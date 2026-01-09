package oba.backend.server.scheduler;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import oba.backend.server.service.AiService;
import org.springframework.cache.CacheManager;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class AiScheduler {

    private final AiService aiService;
    private final CacheManager cacheManager;

    @Scheduled(cron = "0 0 0 * * *", zone = "Asia/Seoul")
    public void runDailyAiTask() {
        log.info("[Scheduler] FastAPI GPT 자동 실행 시작");
        try {
            String result = aiService.runDailyGptTask();
            log.info("[Scheduler] FastAPI 응답: {}", result);

            // Invalidate article caches after new content generation
            evictArticleCaches();
        } catch (Exception e) {
            log.error("[Scheduler] FastAPI 호출 실패", e);
        }
    }

    private void evictArticleCaches() {
        if (cacheManager.getCache("latestArticles") != null) {
            cacheManager.getCache("latestArticles").clear();
        }
        if (cacheManager.getCache("articleDetail") != null) {
            cacheManager.getCache("articleDetail").clear();
        }
    }
}
