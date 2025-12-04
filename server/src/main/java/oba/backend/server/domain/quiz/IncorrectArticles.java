package oba.backend.server.domain.quiz;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Table(name = "incorrect_articles")
@IdClass(IncorrectArticlesId.class)
public class IncorrectArticles {

    @Id
    @Column(name = "user_id")
    private Long userId;

    @Id
    @Column(name = "article_id")
    private Long articleId;

    @Column(name = "sol_date", nullable = false)
    private LocalDateTime solDate;
}
