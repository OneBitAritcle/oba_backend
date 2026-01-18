package oba.backend.server.domain.quiz.entity;

import jakarta.persistence.*;
import lombok.*;
import oba.backend.server.domain.log.entity.ArticleLogId;

import java.util.ArrayList;
import java.util.List;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Table(name = "Incorrect_Quiz")
@IdClass(ArticleLogId.class)
public class IncorrectQuiz {

    @Id
    @Column(name = "user_id")
    private Long userId;

    @Id
    @Column(name = "article_id")
    private Long articleId;

    @Column(nullable = false)
    private boolean quiz1;

    @Column(nullable = false)
    private boolean quiz2;

    @Column(nullable = false)
    private boolean quiz3;

    @Column(nullable = false)
    private boolean quiz4;

    @Column(nullable = false)
    private boolean quiz5;

    // Helper 메서드
    public void setQuizResults(List<Boolean> results) {
        if (results == null || results.size() < 5) return;
        this.quiz1 = results.get(0);
        this.quiz2 = results.get(1);
        this.quiz3 = results.get(2);
        this.quiz4 = results.get(3);
        this.quiz5 = results.get(4);
    }

    public List<Boolean> getQuizResults() {
        List<Boolean> results = new ArrayList<>();
        results.add(quiz1);
        results.add(quiz2);
        results.add(quiz3);
        results.add(quiz4);
        results.add(quiz5);
        return results;
    }
}