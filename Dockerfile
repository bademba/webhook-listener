# Stage 1: Build the application
FROM maven:3.9.9-eclipse-temurin-17 AS build

# Set working directory
WORKDIR /app

# Copy pom.xml and download dependencies
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source code and build
COPY src ./src
RUN mvn clean package -DskipTests

# Stage 2: Run the application
FROM eclipse-temurin:17-jdk-jammy

# Set working directory
WORKDIR /app

# Copy the built jar from the previous stage
COPY --from=build /app/target/*.jar app.jar

# Expose application port
EXPOSE 8080

# Run the jar
ENTRYPOINT ["java","-jar","app.jar"]
