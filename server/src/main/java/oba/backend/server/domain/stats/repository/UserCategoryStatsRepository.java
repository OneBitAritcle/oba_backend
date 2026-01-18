package oba.backend.server.domain.stats.repository;

import oba.backend.server.domain.stats.entity.UserCategoryStats;
import oba.backend.server.domain.stats.entity.UserCategoryId;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface UserCategoryStatsRepository extends JpaRepository<UserCategoryStats, UserCategoryId> {
    List<UserCategoryStats> findByUserId(Long userId);
}