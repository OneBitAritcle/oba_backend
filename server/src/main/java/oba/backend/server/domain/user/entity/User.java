package oba.backend.server.domain.user.entity;

import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import oba.backend.server.domain.stats.entity.UserStats;
import oba.backend.server.global.common.BaseEntity;

@Getter
@NoArgsConstructor
@Entity
@Table(name = "Users")
public class User extends BaseEntity {

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
    @Column(length = 50)
    private Role role;

    @Enumerated(EnumType.STRING)
    @Column(name = "provider", length = 50)
    private AuthProvider authProvider;

    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private UserStats userStats;

    @Builder
    public User(String identifier, String email, String name, String picture, Role role, AuthProvider authProvider) {
        this.identifier = identifier;
        this.email = email;
        this.name = name;
        this.picture = picture;
        this.role = role;
        this.authProvider = authProvider;
    }

    public void updateInfo(String email, String name, String picture) {
        this.email = email;
        this.name = name;
        this.picture = picture;
    }

    public void initStats() {
        if (this.userStats == null) {
            this.userStats = UserStats.builder().user(this).build();
        }
    }

    public void updateStreak() {
        if (this.userStats != null) {
            this.userStats.updateStreak();
        }
    }
}