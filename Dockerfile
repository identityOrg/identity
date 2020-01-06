FROM openjdk:11

ARG JAR_FILE

ADD ${JAR_FILE} app.jar
EXPOSE 8080

ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-jar","/app.jar"]