package oba.backend.server.domain.user;

public enum ProviderInfo {
    GOOGLE,
    KAKAO,
    NAVER,
    MOBILE;

    public static ProviderInfo from(String provider) {
        return ProviderInfo.valueOf(provider.toUpperCase());
    }
}
