package oba.backend.server.auth;

import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.user.ProviderInfo;
import oba.backend.server.domain.user.Role;
import oba.backend.server.domain.user.User;
import oba.backend.server.repository.user.UserRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest request) {

        OAuth2User oAuth2User = super.loadUser(request);

        String provider = request.getClientRegistration().getRegistrationId(); // google,kakao,naver
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

                Map<String, Object> kakaoAccount =
                        (Map<String, Object>) attributes.get("kakao_account");
                Map<String, Object> profile =
                        (Map<String, Object>) kakaoAccount.get("profile");

                email = (String) kakaoAccount.get("email");
                name = (String) profile.get("nickname");
                picture = (String) profile.get("profile_image_url");
            }

            case "naver" -> {
                Map<String, Object> response =
                        (Map<String, Object>) attributes.get("response");

                identifier = "naver:" + response.get("id");
                email = (String) response.get("email");
                name = (String) response.get("name");
                picture = (String) response.get("profile_image");
            }

            default -> throw new IllegalArgumentException("Unsupported provider: " + provider);
        }

        // 사용자 생성 혹은 업데이트
        User user = userRepository.findByIdentifier(identifier)
                .orElseGet(() -> userRepository.save(
                        User.builder()
                                .identifier(identifier)
                                .email(email)
                                .name(name)
                                .picture(picture)
                                .authProvider(ProviderInfo.valueOf(provider.toUpperCase()))
                                .role(Role.USER)
                                .build()
                ));

        return oAuth2User;
    }
}
