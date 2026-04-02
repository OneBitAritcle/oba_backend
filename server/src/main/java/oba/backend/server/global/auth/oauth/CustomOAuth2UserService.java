package oba.backend.server.global.auth.oauth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import oba.backend.server.domain.user.entity.User;
import oba.backend.server.domain.user.service.UserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserService userService;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest request) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(request);
        String registrationId = request.getClientRegistration().getRegistrationId(); // google, kakao, naver

        OAuthAttributes attributes = OAuthAttributes.of(registrationId, oAuth2User.getAttributes());

        String uniqueIdentifier = registrationId + "_" + attributes.identifier();

        OAuth2UserInfo userInfo = OAuth2UserInfo.builder()
                .id(uniqueIdentifier) // DB에 "google_12345" 형태로 저장
                .email(attributes.email())
                .name(attributes.name())
                .picture(attributes.picture())
                .provider(registrationId.toUpperCase())
                .build();

        log.info("OAuth2 User Loaded: Identifier={}", userInfo.getId());

        User user = userService.registerOrUpdateUser(userInfo);

        return new CustomOAuth2User(oAuth2User, user);
    }

    private record OAuthAttributes(String identifier, String email, String name, String picture) {
        static OAuthAttributes of(String provider, Map<String, Object> attributes) {
            return switch (provider.toLowerCase()) {
                case "google" -> ofGoogle(attributes);
                case "kakao" -> ofKakao(attributes);
                case "naver" -> ofNaver(attributes);
                default -> throw new IllegalArgumentException("Unsupported provider: " + provider);
            };
        }

        private static OAuthAttributes ofGoogle(Map<String, Object> attributes) {
            return new OAuthAttributes(
                    (String) attributes.get("sub"),
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
                    String.valueOf(attributes.get("id")),
                    (account != null) ? (String) account.get("email") : null,
                    (profile != null) ? (String) profile.get("nickname") : null,
                    (profile != null) ? (String) profile.get("profile_image_url") : null
            );
        }

        @SuppressWarnings("unchecked")
        private static OAuthAttributes ofNaver(Map<String, Object> attributes) {
            Map<String, Object> response = (Map<String, Object>) attributes.get("response");
            return new OAuthAttributes(
                    (response != null) ? (String) response.get("id") : "",
                    (response != null) ? (String) response.get("email") : null,
                    (response != null) ? (String) response.get("name") : null,
                    (response != null) ? (String) response.get("profile_image") : null
            );
        }
    }
}