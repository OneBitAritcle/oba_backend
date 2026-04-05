package oba.backend.server.domain.ai.scheduler;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import oba.backend.server.domain.ai.service.AiService;
import oba.backend.server.global.common.Const;
import org.springframework.cache.CacheManager;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.Objects;

@Slf4j
@Component
@RequiredArgsConstructor
public class AiScheduler {

    private final AiService aiService;
    private final CacheManager cacheManager;

    // 매일 0시 실행
    @Scheduled(cron = "0 0 0 * * *", zone = "Asia/Seoul")
    public void runDailyAiTask() {
        log.info("[Scheduler] Start Daily GPT Task");
        try {
            String result = aiService.runDailyGptTask();
            log.info("[Scheduler] Result: {}", result);

            // 데이터가 갱신되었으므로 관련 캐시 초기화
            evictCaches();

        } catch (Exception e) {
            log.error("[Scheduler] Error: ", e);
        }
    }

    private void evictCaches() {
        // 모든 리스트 캐시와 상세 캐시를 날림 (단순화 전략)
        Objects.requireNonNull(cacheManager.getCache(Const.CACHE_LATEST_ARTICLES)).clear();
        Objects.requireNonNull(cacheManager.getCache(Const.CACHE_ARTICLE_DETAIL)).clear();
        log.info("[Cache] Article caches evicted.");
    }
}