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

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String name;

    @Column(length = 50)
    private String nickname;

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
    public User(String identifier, String email, String password, String name, String picture, Role role, AuthProvider authProvider) {
        this.identifier = identifier;
        this.email = email;
        this.password = password;
        this.name = name;
        this.picture = picture;
        this.role = role;
        this.authProvider = authProvider;
    }

    public void updateProfile(String name, String picture) {
        if (name != null && !name.isBlank()) this.name = name;
        if (picture != null) this.picture = picture;
    }

    public void updatePassword(String encodedPassword) {
        this.password = encodedPassword;
    }

    public void updateNickname(String nickname) {
        this.nickname = nickname;
    }

    public String getDisplayName() {
        return (nickname != null && !nickname.isBlank()) ? nickname : name;
    }

    public void initStats() {
        if (this.userStats == null) {
            this.userStats = UserStats.builder().user(this).build();
        }
    }

    public void updateStreak() {
        if (this.userStats == null) {
            initStats();
        }
        this.userStats.updateStreak();
    }
}
