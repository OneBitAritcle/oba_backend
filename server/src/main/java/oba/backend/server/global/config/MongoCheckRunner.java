package oba.backend.server.global.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class MongoCheckRunner implements CommandLineRunner {

    private final MongoTemplate mongoTemplate;

    @Override
    public void run(String... args) {
        log.info("==========================================");
        log.info("[MongoDB Connection Check]");
        try {
            String dbName = mongoTemplate.getDb().getName();
            log.info("Connected Database: {}", dbName);

            String collectionName = "Selected_Articles";
            boolean exists = mongoTemplate.collectionExists(collectionName);
            if (exists) {
                long count = mongoTemplate.getCollection(collectionName).countDocuments();
                log.info("Collection '{}' FOUND. (Docs: {} count)", collectionName, count);
            } else {
                log.warn("Collection '{}' NOT FOUND. Article features will be unavailable.", collectionName);
            }
        } catch (Exception e) {
            log.warn("[MongoDB] 연결 실패 - 기사 관련 기능이 제한됩니다: {}", e.getMessage());
        }
        log.info("==========================================");
    }
}
