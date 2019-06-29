#
# Created by Aman LaChapelle on 7/20/18.
#
# peacemakr-core-crypto
# Copyright (c) 2018 peacemakr
# Full license at peacemakr-core-crypto/LICENSE.txt
#

FROM apiaryio/emcc:1.38.11

RUN apt-get update && apt-get install -y --no-install-recommends perl build-essential wget ca-certificates linux-headers-amd64 \
&& apt-get remove -y cmake
RUN wget -qO- "https://cmake.org/files/v3.14/cmake-3.14.3-Linux-x86_64.tar.gz" | tar --strip-components=1 -xz -C /usr/local

ARG CMAKE_BUILD_TYPE=DEBUG
ENV EMSCRIPTEN_BUILD "ON"

ADD CMakeLists.txt /opt/CMakeLists.txt
ADD src/core /opt/src/core
ADD src/ffi/web /opt/src/ffi/web
ADD src/ffi/CMakeLists.txt /opt/src/ffi/CMakeLists.txt
ADD cmake /opt/cmake

# Install emscripten and do the build
WORKDIR /opt/src/ffi/web
RUN cd openssl && ./build-openssl.sh && cd .. \
&& mkdir -p web-build && cd web-build && mkdir -p /opt/corecrypto-build \
&& emconfigure cmake /opt -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DPEACEMAKR_BUILD_WEB=ON \
    -DPEACEMAKR_BUILD_GO=OFF -DPEACEMAKR_BUILD_CPP=OFF -DPEACEMAKR_BUILD_IOS=OFF \
    -DOPENSSL_ROOT_DIR=/opt/src/ffi/web/openssl/build \
    -DOPENSSL_CRYPTO_LIBRARY=/opt/src/ffi/web/openssl/build/lib/libcrypto.a \
    -DOPENSSL_SSL_LIBRARY=/opt/src/ffi/web/openssl/build/lib/libssl.a \
    -DOPENSSL_INCLUDE_DIR=/opt/src/ffi/web/openssl/build/include \
    -DCMAKE_INSTALL_PREFIX=/opt/corecrypto-build \
&& emmake make -j install && cd /opt/corecrypto-build/lib \
&& emcc libpeacemakr-core-crypto.bc -g -o corecrypto.html
