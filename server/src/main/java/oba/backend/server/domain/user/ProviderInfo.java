package oba.backend.server.domain.user;

public enum ProviderInfo {
    LOCAL,
    GOOGLE,
    KAKAO,
    NAVER,
    MOBILE;

    public static ProviderInfo from(String providerName) {
        if (providerName == null) return LOCAL;
        return ProviderInfo.valueOf(providerName.toUpperCase());
    }
}
