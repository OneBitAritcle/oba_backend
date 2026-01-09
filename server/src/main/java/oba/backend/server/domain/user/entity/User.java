package oba.backend.server.doma.user.entity;

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

    @Column
    private String nickname;

    @Column(length = 512)
    private String picture;

    @Enumerated(EnumType.STRING)
    @Column(name = "auth_provider", nullable = false)
    private ProviderInfo authProvider;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    @Builder.Default
    @Column(nullable = false)
    private boolean isDeleted = false;

    public void updateInfo(String email, String name, String picture) {
        if (email != null) this.email = email;
        if (name != null) this.name = name;
        if (picture != null) this.picture = picture;
    }

    public static User createMobileUser(String identifier) {
        return User.builder()
                .identifier(identifier)
                .email(identifier + "@mobile.user")
                .name("모바일유저")
                .picture(null)
                .authProvider(ProviderInfo.MOBILE)
                .role(Role.USER)
                .build();
    }
}
