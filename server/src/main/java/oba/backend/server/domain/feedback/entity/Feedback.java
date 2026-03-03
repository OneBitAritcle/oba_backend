package oba.backend.server.domain.feedback.entity;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.util.Date;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Document(collection = "Feedback")
public class Feedback {

    @Id
    private String id;

    @Field("user_id")
    private Long userId; // Using Long to match User ID type from SQL

    private String content;

    @Field("submitted_at")
    private Date submittedAt;

    @Field("created_at")
    private Date createdAt;

    private String status;
}
