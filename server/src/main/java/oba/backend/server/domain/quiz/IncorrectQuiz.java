package oba.backend.server.domain.quiz;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Table(name = "incorrect_quiz")
@IdClass(IncorrectQuizId.class)
public class IncorrectQuiz {

    @Id
    @Column(name = "user_id")
    private Long userId;

    @Id
    @Column(name = "article_id")
    private Long articleId;

    private boolean quiz1;
    private boolean quiz2;
    private boolean quiz3;
    private boolean quiz4;
    private boolean quiz5;
}
