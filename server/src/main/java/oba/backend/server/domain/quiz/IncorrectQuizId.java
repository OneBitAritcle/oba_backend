package oba.backend.server.domain.quiz;

import lombok.*;
import java.io.Serializable;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class IncorrectQuizId implements Serializable {
    private String userId;
    private Long articleId;
}
