#
# Created by Aman LaChapelle on 7/20/18.
#
# peacemakr-core-crypto
# Copyright (c) 2018 peacemakr
# Full license at peacemakr-core-crypto/LICENSE.txt
#

FROM emscripten/emsdk

RUN apt-get update && apt-get install -y --no-install-recommends perl build-essential curl wget ca-certificates llvm \
&& apt-get remove -y cmake
RUN wget -qO- "https://cmake.org/files/v3.14/cmake-3.14.3-Linux-x86_64.tar.gz" | tar --strip-components=1 -xz -C /usr/local

ADD CMakeLists.txt /opt/CMakeLists.txt
ADD src/core /opt/src/core
ADD src/ffi/web /opt/src/ffi/web
ADD src/ffi/CMakeLists.txt /opt/src/ffi/CMakeLists.txt
ADD cmake /opt/cmake
ADD bin/release-web.sh /opt/bin/release-web.sh

WORKDIR /opt
RUN mkdir -p corecrypto-build && ./bin/release-web.sh

WORKDIR /opt/corecrypto-build/
