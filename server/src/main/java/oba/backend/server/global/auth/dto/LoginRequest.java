package oba.backend.server.global.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

@Getter
public class LoginRequest {

    @NotBlank(message = "idToken은 필수입니다.")
    private String idToken;
}
