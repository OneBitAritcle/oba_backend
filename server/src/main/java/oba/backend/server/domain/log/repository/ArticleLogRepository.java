package oba.backend.server.domain.log.repository;

import oba.backend.server.domain.log.entity.ArticleLog;
import oba.backend.server.domain.log.entity.ArticleLogId;
import org.springframework.data.jpa.repository.JpaRepository;
import java.time.LocalDateTime;
import java.util.List;

public interface ArticleLogRepository extends JpaRepository<ArticleLog, ArticleLogId> {
    List<ArticleLog> findByUserId(Long userId);
    List<ArticleLog> findByUserIdAndIsResolvedFalse(Long userId);
    List<ArticleLog> findByUserIdAndInitialAtGreaterThanEqual(Long userId, LocalDateTime since);
}