FROM eclipse-temurin:17-jdk-focal

COPY build/libs/heylocal-server-0.0.1-SNAPSHOT.jar heylocal.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "heylocal.jar"]
