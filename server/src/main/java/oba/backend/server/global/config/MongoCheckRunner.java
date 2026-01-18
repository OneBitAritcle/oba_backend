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
            // DB 연결 확인
            String dbName = mongoTemplate.getDb().getName();
            log.info("Connected Database: {}", dbName);

            // 컬렉션 존재 여부 확인 (대소문자 구분 중요!)
            String collectionName = "Selected_Articles"; // Entity의 @Document 값과 일치해야 함
            boolean exists = mongoTemplate.collectionExists(collectionName);

            if (exists) {
                long count = mongoTemplate.getCollection(collectionName).countDocuments();
                log.info("Collection '{}' FOUND. (Docs: {} count)", collectionName, count);
            } else {
                log.error("Collection '{}' NOT FOUND!", collectionName);
                log.error("   - Check capitalization (Selected_Articles vs selected_articles)");
                log.error("   - Current Collections: {}", mongoTemplate.getCollectionNames());
            }

        } catch (Exception e) {
            log.error("MongoDB Connection Failed: ", e);
        }
        log.info("==========================================");
    }
}