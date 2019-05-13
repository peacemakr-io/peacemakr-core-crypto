FROM golang:1.11-alpine as builder

RUN apk add --no-cache libbsd-dev git alpine-sdk perl cmake linux-headers

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
&& cmake .. -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} \
   -DPEACEMAKR_BUILD_GO=ON -DPEACEMAKR_BUILD_CPP=OFF -DPEACEMAKR_BUILD_IOS=OFF -DPEACEMAKR_BUILD_ANDROID=OFF \
&& make check install

ENV GOPATH=/go
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

RUN apk add --no-cache gcc musl-dev libbsd-dev
RUN cp -r /opt/src/ffi/go/src /go
WORKDIR /go/src

RUN go test -v peacemakr/crypto

