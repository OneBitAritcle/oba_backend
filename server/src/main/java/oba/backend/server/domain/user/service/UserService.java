package oba.backend.server.domain.user.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import oba.backend.server.domain.user.entity.Role;
import oba.backend.server.domain.user.entity.User;
import oba.backend.server.domain.user.entity.AuthProvider;
import oba.backend.server.domain.user.repository.UserRepository;
import oba.backend.server.global.auth.oauth.OAuth2UserInfo;
import oba.backend.server.global.exception.BusinessException;
import oba.backend.server.global.exception.ErrorCode;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    public User findByIdentifier(String identifier) {
        return userRepository.findByIdentifier(identifier)
                .orElseThrow(() -> {
                    log.warn("[UserService] 유저 조회 실패: identifier={}", identifier);
                    return new BusinessException(ErrorCode.USER_NOT_FOUND);
                });
    }

    @Transactional
    public User registerOrUpdateUser(OAuth2UserInfo info) {
        log.info("[UserService] 로그인 처리: provider={}", info.getProvider());

        AuthProvider providerEnum;
        try {
            providerEnum = AuthProvider.valueOf(info.getProvider().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new BusinessException(ErrorCode.INVALID_INPUT, "지원하지 않는 인증 제공자: " + info.getProvider());
        }

        User user = userRepository.findByIdentifier(info.getId())
                .orElseGet(() -> {
                    log.info("[UserService] 신규 유저 생성");
                    User newUser = User.builder()
                            .identifier(info.getId())
                            .email(info.getEmail())
                            .name(info.getName())
                            .picture(info.getPicture())
                            .role(Role.USER)
                            .authProvider(providerEnum)
                            .build();
                    newUser.initStats();
                    return newUser;
                });

        user.updateInfo(info.getEmail(), info.getName(), info.getPicture());
        return userRepository.save(user);
    }

    @Transactional
    public void updateNickname(String identifier, String nickname) {
        User user = findByIdentifier(identifier);
        user.updateNickname(nickname);
    }

    @Transactional
    public void updateStreak(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        user.updateStreak();
    }
}
