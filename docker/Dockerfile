#
# Created by Aman LaChapelle on 7/20/18.
#
# peacemakr-core-crypto
# Copyright (c) 2018 peacemakr
# Full license at peacemakr-core-crypto/LICENSE.txt
#

FROM debian:latest as builder

# libssl-dev has libssl and libcrypto
RUN apt-get update -y && apt-get install -y pkg-config libbsd-dev wget gnupg software-properties-common openssl libssl-dev make git gcc

ADD "docker/resources/cmake-3.12.0-Linux-x86_64.sh" "/cmake-3.12.0-Linux-x86_64.sh"
RUN mkdir /opt/cmake &&\
        sh /cmake-3.12.0-Linux-x86_64.sh --prefix=/opt/cmake --skip-license &&\
        ln -s /opt/cmake/bin/cmake /usr/local/bin/cmake

WORKDIR /opt

ADD CMakeLists.txt /opt/CMakeLists.txt
ADD src /opt/src
ADD cmake /opt/cmake

RUN mkdir -p build && cd build && cmake .. && make check install

FROM alpine:3.8

COPY --from=builder /usr/local/lib/cmake /usr/local/lib/cmake
COPY --from=builder /usr/local/lib/libpeacemakr* /usr/local/lib/
COPY --from=builder /usr/local/include/peacemakr /usr/local/include/peacemakr
COPY --from=builder /usr/include/openssl /usr/include/openssl
COPY --from=builder /usr/include/x86_64-linux-gnu /usr/include

CMD ["sh"]