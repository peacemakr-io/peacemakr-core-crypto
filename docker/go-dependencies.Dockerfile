FROM golang:1.11-alpine as builder

RUN apk add --no-cache git alpine-sdk perl cmake linux-headers

WORKDIR /opt
RUN git clone -b OpenSSL_1_1_1-stable --single-branch https://github.com/openssl/openssl.git

RUN cd openssl \
    && ./config --prefix=/usr --openssldir=/etc/ssl --libdir=lib no-async \
    && make test MANSUFFIX=ssl install

WORKDIR /opt

ADD CMakeLists.txt /opt/CMakeLists.txt
ADD src/core /opt/src/core
ADD src/ffi/go /opt/src/ffi/go
ADD src/ffi/CMakeLists.txt /opt/src/ffi/CMakeLists.txt
ADD cmake /opt/cmake

ENV GOPATH=/go

ARG CMAKE_BUILD_TYPE=DEBUG
RUN mkdir -p build && cd build \
&& cmake .. \
-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} \
-DCMAKE_INSTALL_PREFIX=/go/src/peacemakr/crypto \
&& make check install \
&& cp -r /usr/include/openssl /go/src/peacemakr/crypto/include/openssl

ENV GOPATH=/go

RUN apk add --no-cache gcc musl-dev
RUN cp -r /opt/src/ffi/go/src /go
WORKDIR /go/src

RUN go test -v peacemakr/crypto
