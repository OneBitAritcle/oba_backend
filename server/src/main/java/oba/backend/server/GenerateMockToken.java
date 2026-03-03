package oba.backend.server;

import oba.backend.server.global.auth.jwt.JwtProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.SpringApplication;
import org.springframework.stereotype.Component;
import org.springframework.boot.CommandLineRunner;

@Component
public class GenerateMockToken implements CommandLineRunner {
    private final JwtProvider jwtProvider;
    public GenerateMockToken(JwtProvider jwtProvider) { this.jwtProvider = jwtProvider; }
    
    @Override
    public void run(String... args) {
        if (args.length > 0 && args[0].equals("gentoken")) {
            System.out.println("Mock Token: " + jwtProvider.createAccessToken(1L, "ROLE_USER"));
            System.exit(0);
        }
    }
}
