package oba.backend.server.security.oauth;

import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.user.ProviderInfo;
import oba.backend.server.domain.user.Role;
import oba.backend.server.domain.user.User;
import oba.backend.server.domain.user.UserRepository;
import oba.backend.server.security.oauth.dto.OAuthAttributes;
import oba.backend.server.security.oauth.dto.CustomOAuth2User;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest request) {

        OAuth2User oauth = super.loadUser(request);

        String provider = request.getClientRegistration().getRegistrationId();
        OAuthAttributes attr = OAuthAttributes.of(provider, oauth.getAttributes());

        User user = saveOrUpdate(attr);

        return new CustomOAuth2User(user, oauth.getAttributes());
    }

    private User saveOrUpdate(OAuthAttributes attr) {

        String identifier = attr.getProvider() + ":" + attr.getEmail();

        return userRepository.findByIdentifier(identifier)
                .map(u -> {
                    u.updateInfo(attr.getEmail(), attr.getName(), attr.getPicture());
                    return userRepository.save(u);
                })
                .orElseGet(() -> userRepository.save(
                        User.builder()
                                .identifier(identifier)
                                .email(attr.getEmail())
                                .name(attr.getName())
                                .picture(attr.getPicture())
                                .provider(ProviderInfo.from(attr.getProvider()))
                                .role(Role.USER)
                                .build()
                ));
    }
}
