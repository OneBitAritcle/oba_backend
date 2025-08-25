package oba.backend.server.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JWT 인증 필터
 * 클라이언트 요청 시 JWT 인증을 하기 위해 만든 필터입니다.
 * OncePerRequestFilter를 상속받아 요청당 한 번만 실행되도록 보장합니다.
 */
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;

    // 실제 필터링 로직을 수행하는 메소드
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 1. Request Header에서 JWT 토큰 추출
        String token = resolveToken(request);

        // 2. validateToken 으로 토큰 유효성 검사
        if (token != null && jwtProvider.validateToken(token)) {
            // 토큰이 유효할 경우 토큰에서 Authentication 객체를 받아옴
            Authentication authentication = jwtProvider.getAuthentication(token);
            // SecurityContext 에 Authentication 객체를 저장
            // 이 과정을 통해 Spring Security는 현재 요청을 처리하는 스레드에서 사용자가 인증되었다고 인식합니다.
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        // 다음 필터로 제어를 넘깁니다.
        filterChain.doFilter(request, response);
    }

    /**
     * Request Header에서 토큰 정보를 추출하는 메소드
     * @param request HttpServletRequest 객체
     * @return 추출된 토큰 문자열
     */
    private String resolveToken(HttpServletRequest request) {
        // "Authorization" 헤더에서 토큰을 가져옵니다.
        String bearerToken = request.getHeader("Authorization");
        // 토큰이 존재하고 "Bearer "로 시작하는지 확인합니다.
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer")) {
            // "Bearer " 접두어를 제거하고 순수한 토큰 값만 반환합니다.
            return bearerToken.substring(7);
        }
        return null;
    }
}
