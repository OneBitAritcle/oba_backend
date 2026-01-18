package oba.backend.server.domain.stats.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Table(name = "User_Category_Stats")
@IdClass(UserCategoryId.class)
public class UserCategoryStats {

    @Id
    @Column(name = "user_id")
    private Long userId;

    @Id
    @Column(name = "category_id")
    private Integer categoryId;

    @Column(name = "total_quizzes")
    @Builder.Default
    private int totalQuizzes = 0;

    @Column(name = "correct_quizzes")
    @Builder.Default
    private int correctQuizzes = 0;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    public void addScore(int total, int correct) {
        this.totalQuizzes += total;
        this.correctQuizzes += correct;
    }
}