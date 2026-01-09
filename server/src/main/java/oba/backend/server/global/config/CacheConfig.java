package oba.backend.server.global.config;

import com.github.benmanes.caffeine.cache.Caffeine;
import oba.backend.server.global.common.Const;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@Configuration
@EnableCaching
public class CacheConfig {

    @Bean
    public Caffeine<Object, Object> caffeineConfig() {
        return Caffeine.newBuilder()
                .initialCapacity(100)
                .maximumSize(5000)
                .expireAfterWrite(30, TimeUnit.MINUTES) // 캐시 만료 시간 30분
                .recordStats();
    }

    @Bean
    public CacheManager cacheManager(Caffeine<Object, Object> caffeine) {
        CaffeineCacheManager manager = new CaffeineCacheManager(
                Const.CACHE_USER,
                Const.CACHE_ARTICLE_DETAIL,
                Const.CACHE_LATEST_ARTICLES
        );
        manager.setCaffeine(caffeine);
        return manager;
    }
}