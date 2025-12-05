package oba.backend.server.auth;

import oba.backend.server.domain.user.ProviderInfo;
import oba.backend.server.domain.user.Role;
import oba.backend.server.domain.user.User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

@Component
public class OAuth2UserConverter {

    public User convert(OAuth2User oAuth2User, String providerName) {

        ProviderInfo provider = ProviderInfo.from(providerName);

        String identifier = providerName + ":" + oAuth2User.getName();

        return User.builder()
                .identifier(identifier)
                .email(oAuth2User.getAttribute("email"))
                .name(oAuth2User.getAttribute("name"))
                .picture(oAuth2User.getAttribute("picture"))
                .authProvider(provider)
                .role(Role.USER)
                .build();
    }
}
