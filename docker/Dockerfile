#
# Created by Aman LaChapelle on 7/20/18.
#
# peacemakr-core-crypto
# Copyright (c) 2018 peacemakr
# Full license at peacemakr-core-crypto/LICENSE.txt
#

FROM debian:latest

# libssl-dev has libssl and libcrypto
RUN apt-get update -y && apt-get install -y pkg-config libbsd-dev wget gnupg software-properties-common openssl libssl-dev make git

RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -

RUN add-apt-repository "deb http://apt.llvm.org/stretch/ llvm-toolchain-stretch-6.0 main"

RUN apt-get update -y && apt-get install -y \
clang-6.0 clang-tools-6.0 llvm-6.0 libfuzzer-6.0-dev lld-6.0 clang-format-6.0

ENV PATH=/usr/lib/llvm-6.0/bin:$PATH

RUN update-alternatives --install /usr/bin/cc cc /usr/lib/llvm-6.0/bin/clang 100

ADD "docker/resources/cmake-3.12.0-Linux-x86_64.sh" "/cmake-3.12.0-Linux-x86_64.sh"
RUN mkdir /opt/cmake &&\
        sh /cmake-3.12.0-Linux-x86_64.sh --prefix=/opt/cmake --skip-license &&\
        ln -s /opt/cmake/bin/cmake /usr/local/bin/cmake

WORKDIR /opt

ADD CMakeLists.txt /opt/CMakeLists.txt
ADD src /opt/src
ADD cmake /opt/cmake

RUN mkdir -p build && cd build && cmake .. && make check install

CMD ["bash"]