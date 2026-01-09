package oba.backend.server.domain.user.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long id;

    @Column(nullable = false, unique = true)
    private String identifier;

    @Column(nullable = false)
    private String email;

    @Column(nullable = false)
    private String name;

    @Column(length = 512)
    private String picture;

    @Enumerated(EnumType.STRING)
    @Column(name = "auth_provider", nullable = false)
    private ProviderInfo authProvider;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    public void updateInfo(String email, String name, String picture) {
        if (email != null && !email.isBlank()) this.email = email;
        if (name != null && !name.isBlank()) this.name = name;
        if (picture != null && !picture.isBlank()) this.picture = picture;
    }
}