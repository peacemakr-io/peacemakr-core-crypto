#
# Created by Aman LaChapelle on 7/20/18.
#
# peacemakr-core-crypto
# Copyright (c) 2018 peacemakr
# Full license at peacemakr-core-crypto/LICENSE.txt
#

FROM trzeci/emscripten:sdk-tag-1.39.4-64bit

ENV EMSCRIPTEN_BUILD "ON"

ADD src/ffi/web /opt/src/ffi/web
WORKDIR /opt/src/ffi/web
RUN cd openssl && ./build-openssl.sh && cd ..

ADD CMakeLists.txt /opt/CMakeLists.txt
ADD bin/static-analysis.sh.in /opt/bin/static-analysis.sh.in
ADD src/core /opt/src/core
ADD src/ffi/CMakeLists.txt /opt/src/ffi/CMakeLists.txt
ADD cmake /opt/cmake

RUN mkdir -p web-build && cd web-build && mkdir -p /opt/corecrypto-build \
&& . ${EMSDK}/emsdk_set_env.sh \
&& emcmake cmake /opt -DCMAKE_BUILD_TYPE=RELEASE -DSTATIC_LIBC=ON -DPEACEMAKR_BUILD_WEB=ON \
    -DOPENSSL_ROOT_DIR=/opt/src/ffi/web/openssl/build \
    -DOPENSSL_CRYPTO_LIBRARY=/opt/src/ffi/web/openssl/build/lib/libcrypto.a \
    -DOPENSSL_SSL_LIBRARY=/opt/src/ffi/web/openssl/build/lib/libssl.a \
    -DOPENSSL_INCLUDE_DIR=/opt/src/ffi/web/openssl/build/include \
    -DCMAKE_INSTALL_PREFIX=/opt/corecrypto-build \
&& emmake make -j install \
&& cd /opt/corecrypto-build/lib \
&& emcc libpeacemakr-core-crypto.* \
   -Os \
   -static-libgcc \
   -L/opt/src/ffi/web/openssl/build/lib \
   -lcrypto -lssl -s EXIT_RUNTIME=1 -s WASM=1 -o corecrypto.js

WORKDIR /opt/corecrypto-build/
