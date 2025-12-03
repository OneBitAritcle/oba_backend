package oba.backend.server.security.oauth.dto;

import lombok.Getter;
import oba.backend.server.domain.user.User;
import oba.backend.server.domain.user.Role;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.List;
import java.util.Map;

@Getter
public class CustomOAuth2User implements OAuth2User {

    private final User user;
    private final Map<String, Object> attributes;

    public CustomOAuth2User(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    // ⭐ 식별자(google:123) 반환
    public String getUserId() {
        return user.getIdentifier();
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    // ⭐ OAuth2User 인터페이스에서 required
    @Override
    public String getName() {
        return user.getName();
    }

    // ⭐ Spring Security가 요구하는 권한 목록
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // User 엔티티의 Role(USER, ADMIN 등) 사용
        Role role = user.getRole();
        return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }
}
