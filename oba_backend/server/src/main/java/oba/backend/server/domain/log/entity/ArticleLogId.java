package oba.backend.server.domain.log.entity;

import lombok.*;
import java.io.Serializable;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
public class ArticleLogId implements Serializable {
    private Long userId;
    private Long articleId;
}