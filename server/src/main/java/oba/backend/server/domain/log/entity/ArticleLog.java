package oba.backend.server.domain.log.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Table(name = "Article_Logs")
@IdClass(ArticleLogId.class)
public class ArticleLog {

    @Id
    @Column(name = "user_id")
    private Long userId;

    @Id
    @Column(name = "article_id")
    private Long articleId;

    @Column(name = "is_resolved", nullable = false)
    @Builder.Default
    private boolean isResolved = false;

    @CreationTimestamp
    @Column(name = "initial_at", nullable = false, updatable = false)
    private LocalDateTime initialAt;

    @Column(name = "resolve_at")
    private LocalDateTime resolveAt;

    public void markAsResolved() {
        this.isResolved = true;
        this.resolveAt = LocalDateTime.now();
    }
}