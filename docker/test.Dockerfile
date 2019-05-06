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

ARG CMAKE_BUILD_TYPE=DEBUG
RUN mkdir -p build && cd build \
&& cmake .. -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DPEACEMAKR_BUILD_GO=OFF -DPEACEMAKR_BUILD_CPP=ON -DPEACEMAKR_BUILD_IOS=OFF \
&& make check install

