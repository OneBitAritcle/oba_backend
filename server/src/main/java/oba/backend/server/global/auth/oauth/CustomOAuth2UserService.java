package oba.backend.server.global.auth.oauth;

import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.user.entity.ProviderInfo;
import oba.backend.server.domain.user.entity.Role;
import oba.backend.server.domain.user.entity.User;
import oba.backend.server.domain.user.service.UserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserService userService;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest request) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(request);
        String registrationId = request.getClientRegistration().getRegistrationId();

        // 1. 복잡한 파싱 로직을 내부 객체(OAuthAttributes)에게 위임
        OAuthAttributes attributes = OAuthAttributes.of(registrationId, oAuth2User.getAttributes());

        // 2. 통합된 유저 조회/생성 메서드 호출
        User user = userService.findOrCreateUser(
                attributes.identifier,
                attributes.email,
                attributes.name,
                attributes.picture,
                ProviderInfo.from(registrationId),
                Role.USER
        );

        return new CustomOAuth2User(oAuth2User, user);
    }

    /**
     * Provider 별로 상이한 속성(Attribute) 정보를 규격화하는 내부 클래스 (Java 17 Record 사용)
     */
    private record OAuthAttributes(String identifier, String email, String name, String picture) {

        static OAuthAttributes of(String provider, Map<String, Object> attributes) {
            return switch (provider) {
                case "google" -> ofGoogle(attributes);
                case "kakao" -> ofKakao(attributes);
                case "naver" -> ofNaver(attributes);
                default -> throw new IllegalArgumentException("Unsupported provider: " + provider);
            };
        }

        private static OAuthAttributes ofGoogle(Map<String, Object> attributes) {
            return new OAuthAttributes(
                    "google:" + attributes.get("sub"),
                    (String) attributes.get("email"),
                    (String) attributes.get("name"),
                    (String) attributes.get("picture")
            );
        }

        @SuppressWarnings("unchecked")
        private static OAuthAttributes ofKakao(Map<String, Object> attributes) {
            Map<String, Object> account = (Map<String, Object>) attributes.get("kakao_account");
            Map<String, Object> profile = (account != null) ? (Map<String, Object>) account.get("profile") : null;

            return new OAuthAttributes(
                    "kakao:" + attributes.get("id"),
                    (account != null) ? (String) account.get("email") : null,
                    (profile != null) ? (String) profile.get("nickname") : null,
                    (profile != null) ? (String) profile.get("profile_image_url") : null
            );
        }

        @SuppressWarnings("unchecked")
        private static OAuthAttributes ofNaver(Map<String, Object> attributes) {
            Map<String, Object> response = (Map<String, Object>) attributes.get("response");
            return new OAuthAttributes(
                    "naver:" + (response != null ? response.get("id") : ""),
                    (response != null) ? (String) response.get("email") : null,
                    (response != null) ? (String) response.get("name") : null,
                    (response != null) ? (String) response.get("profile_image") : null
            );
        }
    }
}