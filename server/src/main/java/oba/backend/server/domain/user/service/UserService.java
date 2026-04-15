package oba.backend.server.domain.user.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import oba.backend.server.domain.user.entity.AuthProvider;
import oba.backend.server.domain.user.entity.Role;
import oba.backend.server.domain.user.entity.User;
import oba.backend.server.domain.user.repository.UserRepository;
import oba.backend.server.global.exception.BusinessException;
import oba.backend.server.global.exception.ErrorCode;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    private static final String PASSWORD_PATTERN =
            "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[@$!%*#?&^()\\-_=+])[A-Za-z\\d@$!%*#?&^()\\-_=+]{8,30}$";

    public User findByIdentifier(String identifier) {
        return userRepository.findByIdentifier(identifier)
                .orElseThrow(() -> {
                    log.warn("[UserService] 유저 조회 실패: identifier={}", identifier);
                    return new BusinessException(ErrorCode.USER_NOT_FOUND);
                });
    }

    @Transactional
    public User register(String email, String password, String name) {
        log.info("[UserService] 회원가입 요청: email={}", email);

        if (userRepository.existsByEmail(email)) {
            throw new BusinessException(ErrorCode.DUPLICATE_EMAIL);
        }

        validatePassword(password);

        String encodedPassword = passwordEncoder.encode(password);

        User user = User.builder()
                .identifier("local_" + email)
                .email(email)
                .password(encodedPassword)
                .name(name)
                .role(Role.USER)
                .authProvider(AuthProvider.LOCAL)
                .build();

        user.initStats();
        User savedUser = userRepository.save(user);
        log.info("[UserService] 회원가입 완료: userId={}", savedUser.getId());
        return savedUser;
    }

    @Transactional(readOnly = true)
    public User login(String email, String rawPassword) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new BusinessException(ErrorCode.INVALID_CREDENTIALS));

        if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
            log.warn("[UserService] 로그인 실패 - 비밀번호 불일치: email={}", email);
            throw new BusinessException(ErrorCode.INVALID_CREDENTIALS);
        }

        log.info("[UserService] 로그인 성공: userId={}", user.getId());
        return user;
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

    @Transactional
    public void changePassword(Long userId, String currentPassword, String newPassword) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));

        if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
            throw new BusinessException(ErrorCode.INVALID_CREDENTIALS, "현재 비밀번호가 일치하지 않습니다.");
        }

        validatePassword(newPassword);
        user.updatePassword(passwordEncoder.encode(newPassword));
        log.info("[UserService] 비밀번호 변경 완료: userId={}", userId);
    }

    @Transactional(readOnly = true)
    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    @Transactional
    public void resetPassword(String email, String name, String newPassword) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND, "등록되지 않은 이메일입니다."));

        if (!user.getName().equals(name)) {
            throw new BusinessException(ErrorCode.INVALID_CREDENTIALS, "이메일과 이름이 일치하지 않습니다.");
        }

        validatePassword(newPassword);
        user.updatePassword(passwordEncoder.encode(newPassword));
        log.info("[UserService] 비밀번호 재설정 완료: email={}", email);
    }

    private void validatePassword(String password) {
        if (password == null || !password.matches(PASSWORD_PATTERN)) {
            throw new BusinessException(ErrorCode.INVALID_PASSWORD_FORMAT);
        }
    }
}
