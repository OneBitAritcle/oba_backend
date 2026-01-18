package oba.backend.server.domain.stats.entity;

import jakarta.persistence.*;
import lombok.*;
import oba.backend.server.domain.user.entity.User;

import java.time.LocalDate;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Table(name = "User_Stats")
public class UserStats {

    @Id
    @Column(name = "user_id")
    private Long userId;

    @OneToOne(fetch = FetchType.LAZY)
    @MapsId
    @JoinColumn(name = "user_id")
    private User user;

    @Column(name = "current_streak")
    @Builder.Default
    private int currentStreak = 0;

    @Column(name = "max_streak")
    @Builder.Default
    private int maxStreak = 0;

    @Column(name = "total_perfect_days")
    @Builder.Default
    private int totalPerfectDays = 0;

    @Column(name = "last_learned_at")
    private LocalDate lastLearnedAt;

    public void updateStreak() {
        LocalDate today = LocalDate.now();
        if (lastLearnedAt != null && lastLearnedAt.equals(today)) return;

        if (lastLearnedAt != null && lastLearnedAt.plusDays(1).equals(today)) {
            this.currentStreak++;
        } else {
            this.currentStreak = 1;
        }

        if (this.currentStreak > this.maxStreak) {
            this.maxStreak = this.currentStreak;
        }
        this.lastLearnedAt = today;
    }
}