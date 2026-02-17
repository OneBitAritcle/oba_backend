FROM amazoncorretto:17

WORKDIR /app

# Gradle Wrapper 복사 및 권한 부여
COPY server/gradlew .
COPY server/gradle gradle
COPY server/build.gradle .
COPY server/settings.gradle .

RUN chmod +x ./gradlew

# 소스 코드 복사
COPY server/src src

# 빌드 (테스트 제외)
RUN ./gradlew bootJar -x test

# 실행 포트 노출
EXPOSE 8080

# JAR 파일 실행 (build/libs/*.jar)
CMD ["java", "-jar", "build/libs/server-0.0.1-SNAPSHOT.jar"]
