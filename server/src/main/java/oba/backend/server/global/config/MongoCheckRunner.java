package oba.backend.server.global.config;

import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.article.repository.GptMongoRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class MongoCheckRunner implements CommandLineRunner {

    private final MongoTemplate mongoTemplate;
    private final GptMongoRepository repository;

    @Override
    public void run(String... args) throws Exception {
        System.out.println("==========================================");
        System.out.println("[MongoDB 연결 확인]");

        // 1. 현재 연결된 데이터베이스 이름 출력
        try {
            String dbName = mongoTemplate.getDb().getName();
            System.out.println("연결된 DB 이름: " + dbName);
        } catch (Exception e) {
            System.out.println("DB 연결 실패: " + e.getMessage());
        }

        // 2. Repository를 통해 데이터 개수 조회
        try {
            long count = repository.count();
            System.out.println("👉 'Selected_Articles' 컬렉션 데이터 개수: " + count + "개");

            if (count == 0) {
                System.out.println("데이터가 0개입니다. 컬렉션 이름(@Document)이나 DB 주소를 확인하세요!");
                System.out.println("현재 DB에 존재하는 컬렉션 목록: " + mongoTemplate.getCollectionNames());
            } else {
                System.out.println("데이터가 존재합니다! API 조회를 다시 시도해보세요.");
            }
        } catch (Exception e) {
            System.out.println("조회 중 에러 발생: " + e.getMessage());
        }

        System.out.println("==========================================");
    }
}