package oba.backend.server.auth;

import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.user.ProviderInfo;
import oba.backend.server.domain.user.Role;
import oba.backend.server.domain.user.User;
import oba.backend.server.service.UserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserService userService;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest request) {
        OAuth2User oAuth2User = super.loadUser(request);

        String provider = request.getClientRegistration().getRegistrationId(); // google / kakao / naver
        Map<String, Object> attributes = oAuth2User.getAttributes();

        String identifier;
        String email;
        String name;
        String picture;

        switch (provider) {
            case "google" -> {
                identifier = "google:" + attributes.get("sub");
                email = (String) attributes.get("email");
                name = (String) attributes.get("name");
                picture = (String) attributes.get("picture");
            }
            case "kakao" -> {
                identifier = "kakao:" + attributes.get("id");
                Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
                Map<String, Object> profile = kakaoAccount == null ? null : (Map<String, Object>) kakaoAccount.get("profile");

                email = kakaoAccount == null ? null : (String) kakaoAccount.get("email");
                name = profile == null ? null : (String) profile.get("nickname");
                picture = profile == null ? null : (String) profile.get("profile_image_url");
            }
            case "naver" -> {
                Map<String, Object> response = (Map<String, Object>) attributes.get("response");
                identifier = "naver:" + (response == null ? null : response.get("id"));
                email = response == null ? null : (String) response.get("email");
                name = response == null ? null : (String) response.get("name");
                picture = response == null ? null : (String) response.get("profile_image");
            }
            default -> throw new IllegalArgumentException("Unsupported provider: " + provider);
        }

        if (identifier == null) {
            throw new IllegalStateException("OAuth2 identifier is null for provider: " + provider);
        }

        User user = userService.findOrCreateOAuthUser(
                identifier,
                email,
                name,
                picture,
                ProviderInfo.valueOf(provider.toUpperCase()),
                Role.USER
        );

        return new CustomOAuth2User(oAuth2User, user);
    }
}
