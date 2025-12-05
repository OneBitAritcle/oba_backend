package oba.backend.server.service;

import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.user.User;
import oba.backend.server.repository.user.UserRepository;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MobileAuthService {

    private final UserRepository userRepository;

    public User findOrCreateMobileUser(String identifier) {
        return userRepository.findByIdentifier(identifier)
                .orElseGet(() -> userRepository.save(User.createMobileUser(identifier)));
    }
}
