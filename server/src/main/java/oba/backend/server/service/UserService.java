package oba.backend.server.service;

import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.user.User;
import oba.backend.server.domain.user.UserRepository;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    public User findOrCreate(String email, String name) {

        return userRepository.findByEmail(email)
                .orElseGet(() -> {
                    User user = User.builder()
                            .email(email)
                            .name(name)
                            .build();
                    return userRepository.save(user);
                });
    }
}
