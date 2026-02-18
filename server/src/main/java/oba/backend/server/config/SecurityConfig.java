package oba.backend.server.config;

import lombok.RequiredArgsConstructor;
import oba.backend.server.security.CustomAuthorizationRequestResolver;
import oba.backend.server.security.CustomOAuth2UserService;
import oba.backend.server.security.OAuth2SuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomAuthorizationRequestResolver customAuthorizationRequestResolver;
    private final OAuth2SuccessHandler oAuth2SuccessHandler;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        AuthenticationFailureHandler keepSessionFailure =
                (request, response, exception) ->
                        response.sendRedirect("/login?error=" + exception.getClass().getSimpleName());

        http
                .csrf(csrf -> csrf.disable())
                .formLogin(form -> form.disable())
                .httpBasic(b -> b.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/ai/**").permitAll()

                        .requestMatchers("/", "/login", "/error",
                                "/oauth2/**", "/css/**", "/js/**", "/images/**", "/img/**").permitAll()

                        .anyRequest().authenticated()
                )
                .oauth2Login(o -> o
                        .loginPage("/login")
                        .authorizationEndpoint(a -> a.authorizationRequestResolver(customAuthorizationRequestResolver))
                        .userInfoEndpoint(u -> u.userService(customOAuth2UserService))
                        .successHandler(oAuth2SuccessHandler)
                        .failureHandler(keepSessionFailure)
                )
                .logout(l -> l
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .deleteCookies("JSESSIONID","refresh_token")
                        .invalidateHttpSession(true)
                );

        return http.build();
    }
}
