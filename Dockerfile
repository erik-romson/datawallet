# Stage 1: resolve all dependencies (rebuilds only when POMs change)
FROM eclipse-temurin:25-jdk AS deps
ARG MAVEN_VERSION=3.9.9
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL "https://archive.apache.org/dist/maven/maven-3/${MAVEN_VERSION}/binaries/apache-maven-${MAVEN_VERSION}-bin.tar.gz" \
    | tar -xzC /opt \
 && ln -s "/opt/apache-maven-${MAVEN_VERSION}/bin/mvn" /usr/local/bin/mvn
WORKDIR /build
COPY parent/pom.xml parent/pom.xml
COPY pom.xml pom.xml
COPY intermediate/pom.xml intermediate/pom.xml
RUN mvn -B -f parent/pom.xml install -N \
 && mvn -B -f pom.xml dependency:go-offline \
 && mvn -B -f intermediate/pom.xml dependency:go-offline

# Stage 2: build server fat jar
FROM deps AS build-server
COPY src/ src/
RUN mvn -B -f pom.xml -DskipTests package

# Stage 3: build intermediate fat jar
FROM deps AS build-intermediate
COPY intermediate/src/ intermediate/src/
RUN mvn -B -f intermediate/pom.xml -DskipTests package

# Stage 4: build minimal JRE via jlink (~75 MB)
FROM eclipse-temurin:25-jdk AS jre
RUN jlink \
      --no-header-files \
      --no-man-pages \
      --strip-debug \
      --compress=2 \
      --add-modules \
        java.base,java.compiler,java.desktop,java.instrument,java.logging,\
java.management,java.naming,java.net.http,java.prefs,java.rmi,\
java.scripting,java.security.jgss,java.security.sasl,java.sql,\
java.transaction.xa,java.xml,jdk.crypto.cryptoki,jdk.crypto.ec,\
jdk.jdwp.agent,jdk.management,jdk.unsupported \
      --output /opt/jre

# Stage 5: server runtime image
FROM gcr.io/distroless/java-base-debian12:nonroot AS server
COPY --from=jre /opt/jre /opt/jre
COPY --from=build-server /build/target/datawallet-*.jar /app/app.jar
USER nonroot:nonroot
EXPOSE 8443
ENTRYPOINT ["/opt/jre/bin/java", "-jar", "/app/app.jar"]

# Stage 6: intermediate runtime image
FROM gcr.io/distroless/java-base-debian12:nonroot AS intermediate
COPY --from=jre /opt/jre /opt/jre
COPY --from=build-intermediate /build/intermediate/target/datawallet-intermediate-*.jar /app/app.jar
USER nonroot:nonroot
EXPOSE 8444
ENTRYPOINT ["/opt/jre/bin/java", "-jar", "/app/app.jar"]
