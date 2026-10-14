# docker/log4shell-2021-44228.Dockerfile
# Java-приложение с уязвимым Log4j 2.14.1 (CVE-2021-44228).
# Простой HTTP-сервер на Spring Boot, логирует User-Agent через Log4j.

FROM maven:3.8-openjdk-11 AS builder

WORKDIR /build

# Простой HTTP-сервер, логирующий заголовки
RUN mkdir -p src/main/java/demo && \
    printf '%s\n' \
'package demo;' \
'import org.springframework.boot.SpringApplication;' \
'import org.springframework.boot.autoconfigure.SpringBootApplication;' \
'import org.springframework.web.bind.annotation.*;' \
'import org.apache.logging.log4j.LogManager;' \
'import org.apache.logging.log4j.Logger;' \
'import javax.servlet.http.HttpServletRequest;' \
'@SpringBootApplication' \
'@RestController' \
'public class App {' \
'    private static final Logger log = LogManager.getLogger(App.class);' \
'    public static void main(String[] args) {' \
'        SpringApplication.run(App.class, args);' \
'    }' \
'    @GetMapping("/")' \
'    public String index(HttpServletRequest req) {' \
'        String ua = req.getHeader("User-Agent");' \
'        log.info("Request from User-Agent: {}", ua);' \
'        return "ok";' \
'    }' \
'}' \
> src/main/java/demo/App.java

# pom.xml с Log4j 2.14.1 (уязвимая версия)
RUN printf '%s\n' \
'<?xml version="1.0"?>' \
'<project xmlns="http://maven.apache.org/POM/4.0.0">' \
'  <modelVersion>4.0.0</modelVersion>' \
'  <groupId>demo</groupId>' \
'  <artifactId>log4shell</artifactId>' \
'  <version>1.0</version>' \
'  <parent>' \
'    <groupId>org.springframework.boot</groupId>' \
'    <artifactId>spring-boot-starter-parent</artifactId>' \
'    <version>2.5.0</version>' \
'  </parent>' \
'  <dependencies>' \
'    <dependency>' \
'      <groupId>org.springframework.boot</groupId>' \
'      <artifactId>spring-boot-starter-web</artifactId>' \
'      <exclusions>' \
'        <exclusion>' \
'          <groupId>org.springframework.boot</groupId>' \
'          <artifactId>spring-boot-starter-logging</artifactId>' \
'        </exclusion>' \
'      </exclusions>' \
'    </dependency>' \
'    <dependency>' \
'      <groupId>org.apache.logging.log4j</groupId>' \
'      <artifactId>log4j-core</artifactId>' \
'      <version>2.14.1</version>' \
'    </dependency>' \
'    <dependency>' \
'      <groupId>org.apache.logging.log4j</groupId>' \
'      <artifactId>log4j-api</artifactId>' \
'      <version>2.14.1</version>' \
'    </dependency>' \
'  </dependencies>' \
'  <properties>' \
'    <java.version>11</java.version>' \
'  </properties>' \
'</project>' \
> pom.xml

RUN mvn -q package -DskipTests

FROM openjdk:11-jre-slim

WORKDIR /app
COPY --from=builder /build/target/log4shell-1.0.jar app.jar

EXPOSE 8080
CMD ["java", "-jar", "app.jar"]
