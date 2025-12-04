package oba.backend.server.domain.user;

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

    /** 모바일: "mobile:xxxxx", 구글: "google:xxxx" */
    @Column(nullable = false, unique = true)
    private String identifier;

    @Column(nullable = false)
    private String email;

    @Column(nullable = false)
    private String name;

    /** 신규 추가 — nickname(default null → DB 트리거로 자동 처리) */
    @Column
    private String nickname;

    @Column(length = 512)
    private String picture;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ProviderInfo provider;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    @Column(nullable = false)
    private boolean isDeleted = false;

    /** 로그인 시 정보 업데이트 */
    public void updateInfo(String email, String name, String picture) {
        this.email = email;
        this.name = name;
        this.picture = picture;
    }

    /** 모바일 회원 생성 */
    public static User createMobileUser(String identifier) {
        return User.builder()
                .identifier(identifier)
                .email(identifier + "@mobile.user")
                .name("모바일유저")
                .nickname(null)   // DB 트리거에서 자동 name → nickname
                .provider(ProviderInfo.MOBILE)
                .role(Role.USER)
                .build();
    }

    /** 구글 로그인 신규 생성 */
    public static User createGoogleUser(String identifier, String email, String name, String picture) {
        return User.builder()
                .identifier(identifier)
                .email(email)
                .name(name)
                .nickname(null)   // 트리거에서 자동 설정
                .picture(picture)
                .provider(ProviderInfo.GOOGLE)
                .role(Role.USER)
                .build();
    }
}
