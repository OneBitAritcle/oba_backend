package oba.backend.server.config.env;

import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.Ordered;
import org.springframework.core.io.ClassPathResource;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.*;

public class EnvVarPostProcessor implements EnvironmentPostProcessor, Ordered {

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, org.springframework.boot.SpringApplication application) {
        try {
            var resource = new ClassPathResource(".env");
            if (!resource.exists()) return;

            Map<String, Object> map = new HashMap<>();

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(resource.getInputStream()))) {

                String line;
                while ((line = reader.readLine()) != null) {
                    // 공백 제거 + BOM 제거
                    line = line.replace("\uFEFF", "").trim();

                    if (line.isEmpty() || line.startsWith("#")) continue;
                    if (!line.contains("=")) continue;

                    String[] parts = line.split("=", 2);

                    String key = parts[0].replace("\r", "").trim();
                    String value = parts[1].replace("\r", "").trim();

                    map.put(key, value);
                }
            }

            environment.getPropertySources()
                    .addFirst(new MapPropertySource("customEnvVars", map));

        } catch (Exception e) {
            System.out.println("EnvVarPostProcessor error: " + e.getMessage());
        }
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
