#
# Created by Aman LaChapelle on 7/20/18.
#
# peacemakr-core-crypto
# Copyright (c) 2018 peacemakr
# Full license at peacemakr-core-crypto/LICENSE.txt
#

FROM alpine:3.8 as builder

RUN apk add --no-cache libbsd-dev git alpine-sdk perl cmake linux-headers

WORKDIR /opt
RUN git clone -b OpenSSL_1_1_1-stable --single-branch https://github.com/openssl/openssl.git

RUN cd openssl \
    && ./config --prefix=/usr --openssldir=/etc/ssl --libdir=lib no-async \
    && make test MANSUFFIX=ssl install

WORKDIR /opt

ADD CMakeLists.txt /opt/CMakeLists.txt
ADD src /opt/src
ADD cmake /opt/cmake

ENV GOPATH=/go

ARG CMAKE_BUILD_TYPE=DEBUG
RUN mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DPEACEMAKR_BUILD_GO=ON && make check install

FROM golang:alpine3.8

RUN apk add --no-cache gcc musl-dev libbsd-dev

COPY --from=builder /usr/local/lib/cmake /usr/local/lib/cmake
COPY --from=builder /usr/local/lib/libpeacemakr* /usr/local/lib/
COPY --from=builder /usr/local/include/peacemakr /usr/local/include/peacemakr
COPY --from=builder /usr/include/openssl /usr/include/openssl
COPY --from=builder /opt/src/ffi/go/src /go/src

ENV GOPATH=/go
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

WORKDIR /go/src

RUN go test -v peacemakr/crypto
