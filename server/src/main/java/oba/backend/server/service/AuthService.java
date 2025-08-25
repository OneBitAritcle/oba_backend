package oba.backend.server.service;

import lombok.RequiredArgsConstructor;
import oba.backend.server.dto.AuthDto.LoginRequest;
import oba.backend.server.dto.AuthDto.SignUpRequest;
import oba.backend.server.dto.AuthDto.TokenResponse;
import oba.backend.server.entity.Member;
import oba.backend.server.jwt.JwtProvider;
import oba.backend.server.repository.MemberRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import oba.backend.server.security.CustomUserDetailsService;

import java.time.Duration;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;
    private final AuthenticationManager authenticationManager;
    private final CustomUserDetailsService customUserDetailsService;
    private final RedisTemplate<String, String> redisTemplate; // RedisTemplate 주입

    @Value("${jwt.refresh-token-expiration-ms}")
    private long refreshTokenExpirationMs; // Refresh Token 만료 시간 주입

    @Transactional
    public void signUp(SignUpRequest signUpRequest) {
        if (memberRepository.existsByUsername(signUpRequest.username())) {
            throw new RuntimeException("이미 사용 중인 아이디입니다.");
        }

        String encodedPassword = passwordEncoder.encode(signUpRequest.password());
        Member member = Member.builder()
                .username(signUpRequest.username())
                .password(encodedPassword)
                .build();
        memberRepository.save(member);
    }

    @Transactional
    public void deleteMember() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication.getName() == null) {
            throw new RuntimeException("인증 정보가 없는 요청입니다.");
        }
        String username = authentication.getName();

        Member member = memberRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));

        // Redis에서도 Refresh Token 삭제
        redisTemplate.delete(username);
        memberRepository.delete(member);
    }

    @Transactional
    public TokenResponse login(LoginRequest loginRequest) {
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginRequest.username(), loginRequest.password());
        Authentication authentication = authenticationManager.authenticate(authenticationToken);

        TokenResponse tokenResponse = jwtProvider.generateToken(authentication);

        // Redis에 Refresh Token 저장 (Key: username, Value: refreshToken)
        redisTemplate.opsForValue().set(
                authentication.getName(),
                tokenResponse.refreshToken(),
                Duration.ofMillis(refreshTokenExpirationMs)
        );

        return tokenResponse;
    }

    @Transactional
    public TokenResponse reissue(String refreshToken) {
        // 1. Refresh Token 유효성 검사
        if (!jwtProvider.validateToken(refreshToken)) {
            throw new RuntimeException("유효하지 않은 Refresh Token 입니다.");
        }

        // 2. Refresh Token에서 사용자 이름(username) 가져오기
        String username = jwtProvider.getUsernameFromToken(refreshToken);
        if (username == null) {
            throw new RuntimeException("Refresh Token에서 사용자 정보를 찾을 수 없습니다.");
        }

        // 3. Redis에 저장된 Refresh Token과 비교
        String storedRefreshToken = redisTemplate.opsForValue().get(username);
        if (storedRefreshToken == null || !storedRefreshToken.equals(refreshToken)) {
            throw new RuntimeException("유효하지 않거나 로그아웃된 Refresh Token 입니다.");
        }

        // 4. 새로운 토큰 생성
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);
        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        TokenResponse tokenResponse = jwtProvider.generateToken(authentication);

        // 5. Redis에 새로운 Refresh Token 저장
        redisTemplate.opsForValue().set(
                username,
                tokenResponse.refreshToken(),
                Duration.ofMillis(refreshTokenExpirationMs)
        );

        return tokenResponse;
    }

    @Transactional
    public void logout() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication.getName() == null) {
            throw new RuntimeException("인증 정보가 없는 요청입니다.");
        }
        String username = authentication.getName();

        // Redis에서 해당 사용자의 Refresh Token 삭제
        if (redisTemplate.opsForValue().get(username) != null) {
            redisTemplate.delete(username);
        }
    }
}