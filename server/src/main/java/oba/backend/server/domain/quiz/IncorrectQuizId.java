package oba.backend.server.domain.quiz;

import lombok.*;
import java.io.Serializable;
import java.util.Objects;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class IncorrectQuizId implements Serializable {

    private Long userId;
    private Long articleId;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof IncorrectQuizId)) return false;
        IncorrectQuizId that = (IncorrectQuizId) o;
        return Objects.equals(userId, that.userId) &&
                Objects.equals(articleId, that.articleId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId, articleId);
    }
}
