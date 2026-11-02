# Multi-stage build for Maven SemVer service
# Compatible with both AMD64 and ARM64 (Apple Silicon)

FROM maven:3.9-eclipse-temurin-17 AS builder
WORKDIR /app

COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

FROM eclipse-temurin:17-jre
WORKDIR /app

COPY --from=builder /app/target/maven.semver.jar /app/maven.semver.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "maven.semver.jar"]
