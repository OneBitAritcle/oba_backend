package oba.backend.server.domain.stats.repository;

import oba.backend.server.domain.stats.entity.UserStats;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserStatsRepository extends JpaRepository<UserStats, Long> {
}