package oba.backend.server.domain.stats.entity;

import lombok.*;
import java.io.Serializable;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
public class UserCategoryId implements Serializable {
    private Long userId;
    private Integer categoryId;
}