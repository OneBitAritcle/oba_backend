package oba.backend.server.doma.user.service;

import lombok.RequiredArgsConstructor;
import oba.backend.server.doma.user.entity.ProviderInfo;
import oba.backend.server.doma.user.entity.Role;
import oba.backend.server.doma.user.entity.User;
import oba.backend.server.doma.user.repository.UserRepository;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    @Cacheable(value = "userByIdentifier", key = "#identifier", unless = "#result == null")
    public User findByIdentifier(String identifier) {
        return userRepository.findByIdentifier(identifier).orElse(null);
    }

    @CacheEvict(value = "userByIdentifier", key = "#identifier")
    public User findOrCreateOAuthUser(String identifier,
                                      String email,
                                      String name,
                                      String picture,
                                      ProviderInfo provider,
                                      Role role) {
        return userRepository.findByIdentifier(identifier)
                .map(existing -> {
                    existing.updateInfo(email, name, picture);
                    return userRepository.save(existing);
                })
                .orElseGet(() -> userRepository.save(
                        User.builder()
                                .identifier(identifier)
                                .email(email != null ? email : (identifier + "@oauth.user"))
                                .name(name != null ? name : "OAuthUser")
                                .picture(picture)
                                .authProvider(provider)
                                .role(role)
                                .build()
                ));
    }
}
