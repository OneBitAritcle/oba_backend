package oba.backend.server.domain.user.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import oba.backend.server.domain.user.entity.Role;
import oba.backend.server.domain.user.entity.User;
import oba.backend.server.domain.user.entity.AuthProvider;
import oba.backend.server.domain.user.repository.UserRepository;
import oba.backend.server.global.auth.oauth.OAuth2UserInfo;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    // 유저 조회 log
    public User findByIdentifier(String identifier) {
        log.info("[UserService] findByIdentifier 호출됨. 찾는 ID: '{}'", identifier);

        return userRepository.findByIdentifier(identifier)
                .orElseThrow(() -> {
                    log.error(" [UserService] DB 조회 실패! ID: '{}' 인 유저가 테이블에 없습니다.", identifier);
                    return new IllegalArgumentException("유저를 찾을 수 없습니다.");
                });
    }

    // 유저 등록/수정 log
    @Transactional
    public User registerOrUpdateUser(OAuth2UserInfo info) {
        log.info(" [UserService] registerOrUpdateUser 호출됨. Provider: {}, ID: {}", info.getProvider(), info.getId());

        AuthProvider providerEnum = AuthProvider.valueOf(info.getProvider().toUpperCase());

        User user = userRepository.findByIdentifier(info.getId())
                .orElseGet(() -> {
                    log.info("[UserService] 신규 유저 생성 시작 ID: {}", info.getId());
                    User newUser = User.builder()
                            .identifier(info.getId())
                            .email(info.getEmail())
                            .name(info.getName())
                            .picture(info.getPicture())
                            .role(Role.USER)
                            .authProvider(providerEnum)
                            .build();
                    newUser.initStats(); // 통계 초기화
                    return newUser;
                });

        user.updateInfo(info.getEmail(), info.getName(), info.getPicture());
        User savedUser = userRepository.save(user);

        log.info(" [UserService] 저장 완료. DB PK: {}, Identifier: {}", savedUser.getId(), savedUser.getIdentifier());
        return savedUser;
    }

    @Transactional
    public void updateStreak(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("유저 없음"));
        user.updateStreak();
    }
}