package oba.backend.server.global.auth.oauth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OAuth2UserInfo {
    private String id;
    private String email;
    private String name;
    private String picture;
    private String provider;
}