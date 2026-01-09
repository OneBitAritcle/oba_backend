package oba.backend.server.domain.user.service;

import lombok.RequiredArgsConstructor;

import oba.backend.server.domain.user.entity.ProviderInfo;
import oba.backend.server.domain.user.entity.Role;
import oba.backend.server.domain.user.entity.User;
import oba.backend.server.domain.user.repository.UserRepository;
import oba.backend.server.global.common.Const;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    @Cacheable(value = Const.CACHE_USER, key = "#identifier", unless = "#result == null")
    @Transactional(readOnly = true)
    public User findByIdentifier(String identifier) {
        return userRepository.findByIdentifier(identifier).orElse(null);
    }

    /**
     * 유저 생성 혹은 정보 업데이트 (로그인 시 호출)
     * 정보가 변경될 수 있으므로 해당 유저의 캐시를 삭제(@CacheEvict)합니다.
     */
    @Transactional
    @CacheEvict(value = Const.CACHE_USER, key = "#identifier")
    public User findOrCreateUser(String identifier, String email, String name, String picture, ProviderInfo provider, Role role) {
        return userRepository.findByIdentifier(identifier)
                .map(user -> {
                    user.updateInfo(email, name, picture);
                    return user;
                })
                .orElseGet(() -> userRepository.save(User.builder()
                        .identifier(identifier)
                        .email(email != null ? email : identifier + "@unknown")
                        .name(name != null ? name : "User")
                        .picture(picture)
                        .authProvider(provider)
                        .role(role)
                        .build()));
    }
}