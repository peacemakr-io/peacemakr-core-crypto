FROM openjdk:12-alpine

RUN apk add --no-cache git alpine-sdk perl cmake linux-headers libgcc musl-dev

WORKDIR /opt
RUN git clone -b OpenSSL_1_1_1-stable --single-branch https://github.com/openssl/openssl.git

RUN cd openssl \
    && ./config --prefix=/usr --openssldir=/etc/ssl --libdir=lib no-async \
    && make test MANSUFFIX=ssl install

WORKDIR /opt

ADD CMakeLists.txt /opt/CMakeLists.txt
ADD src/core /opt/src/core
# Gradle
ADD src/ffi/java/gradle /opt/src/ffi/java/gradle
ADD src/ffi/java/gradlew /opt/src/ffi/java/gradlew
ADD src/ffi/java/build.gradle /opt/src/ffi/java/build.gradle
# C code
ADD src/ffi/java/src/main/c /opt/src/ffi/java/src/main/c
# Java code
ADD src/ffi/java/src/main/java /opt/src/ffi/java/src/main/java
# Test code
ADD src/ffi/java/src/test /opt/src/ffi/java/src/test
# Build requirements
ADD src/ffi/CMakeLists.txt /opt/src/ffi/CMakeLists.txt
ADD cmake /opt/cmake

WORKDIR /opt/src/ffi/java
ARG BUILD_TYPE
RUN ./gradlew clean && ./gradlew makeInstall -P${BUILD_TYPE}
