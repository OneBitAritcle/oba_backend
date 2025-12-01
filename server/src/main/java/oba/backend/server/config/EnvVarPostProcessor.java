package oba.backend.server.config.env;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.HashMap;
import java.util.Map;

public class EnvVarPostProcessor implements EnvironmentPostProcessor, Ordered {

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {

        try {
            File envFile = new File(".env");   // ★ 실행 위치(server/)의 .env 를 로드

            if (!envFile.exists()) {
                System.out.println("[EnvPostProcessor] .env not found in working directory");
                return;
            }

            Map<String, Object> map = new HashMap<>();

            try (BufferedReader reader = new BufferedReader(new FileReader(envFile))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("#")) continue;

                    if (!line.contains("=")) continue;

                    String[] parts = line.split("=", 2);
                    String key = parts[0].trim();
                    String value = parts.length > 1 ? parts[1].trim() : "";

                    map.put(key, value);
                }
            }

            environment.getPropertySources()
                    .addFirst(new MapPropertySource("customEnvVars", map));

            System.out.println("[EnvPostProcessor] .env loaded successfully from server/");

        } catch (Exception e) {
            System.out.println("[EnvPostProcessor] Error loading .env: " + e.getMessage());
        }
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
