package oba.backend.server.config;

import lombok.RequiredArgsConstructor;
import oba.backend.server.common.jwt.JwtAuthenticationFilter;
import oba.backend.server.security.oauth.CustomOAuth2UserService;
import oba.backend.server.security.oauth.OAuth2SuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtFilter;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2SuccessHandler oAuth2SuccessHandler;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .cors(c -> c.configurationSource(req -> {
                    CorsConfiguration config = new CorsConfiguration();
                    config.setAllowCredentials(true);
                    config.setAllowedOrigins(List.of("*"));
                    config.setAllowedHeaders(List.of("*"));
                    config.setAllowedMethods(List.of("*"));
                    return config;
                }))

                .csrf(csrf -> csrf.disable())

                .sessionManagement(s ->
                        s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/**", "/oauth2/**", "/login/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/articles/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/gpt/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/ai/**").permitAll()
                        .anyRequest().authenticated()
                )

                .oauth2Login(oauth -> oauth
                        .userInfoEndpoint(c -> c.userService(customOAuth2UserService))
                        .successHandler(oAuth2SuccessHandler)
                )

                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
            throws Exception {
        return config.getAuthenticationManager();
    }
}
