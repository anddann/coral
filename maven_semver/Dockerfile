FROM openjdk:8

COPY ./target/maven.semver-1.1-jar-with-dependencies.jar /usr/app/

WORKDIR /usr/app

RUN sh -c 'touch maven.semver-1.1-jar-with-dependencies.jar'

ENTRYPOINT ["java","-jar","maven.semver-1.1-jar-with-dependencies.jar"]
