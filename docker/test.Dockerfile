#
# Created by Aman LaChapelle on 7/20/18.
#
# peacemakr-core-crypto
# Copyright (c) 2018 peacemakr
# Full license at peacemakr-core-crypto/LICENSE.txt
#

FROM alpine:3.8 as builder

RUN apk add --no-cache git alpine-sdk perl cmake linux-headers clang-analyzer clang-dev llvm5-dev compiler-rt

WORKDIR /opt
RUN git clone -b OpenSSL_1_1_1-stable --single-branch https://github.com/openssl/openssl.git

RUN cd openssl \
    && ./config --prefix=/usr --openssldir=/etc/ssl --libdir=lib no-async \
    && make test MANSUFFIX=ssl install

WORKDIR /opt

ADD CMakeLists.txt /opt/CMakeLists.txt
ADD src /opt/src
ADD cmake /opt/cmake

RUN mkdir -p analysis_build && cd analysis_build && /usr/bin/scan-build cmake .. && /usr/bin/scan-build make && cd ..

# If you want to mount a corpus for fuzzing, mount it into /opt/CORPUS
RUN mkdir -p /opt/CORPUS

RUN mkdir -p build && cd build && CC=clang CXX=clang++ cmake .. -DPEACEMAKR_BUILD_CPP=ON && make check && make test_fuzz

CMD /opt/build/test_fuzz /opt/CORPUS -max_len=16384 -jobs=4
