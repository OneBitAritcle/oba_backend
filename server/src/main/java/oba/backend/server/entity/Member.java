package oba.backend.server.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    private String refreshToken; // 리프레시 토큰 저장

    @Builder
    public Member(String username, String password) {
        this.username = username;
        this.password = password;
    }

    // 리프레시 토큰 업데이트
//    public void updateRefreshToken(String refreshToken) {
//        this.refreshToken = refreshToken;
//    }
}