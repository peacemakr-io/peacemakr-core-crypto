#!/usr/bin/env bash

set -ex

function usage {
    echo "Usage: ./bin/release-web.sh [path to peacemakr-js folder] [optional: release]"
    echo "Make sure you've installed emscripten (brew install emscripten)"
    echo "for example, ./bin/release-web.sh ~/peacemakr/peacemakr-js release"
}

if [[ "$#" -gt 2 ]]; then
    echo "Illegal use"
    usage
    exit 1
fi

function get_crypto_file {
    out_dir=${1}

    pushd src/ffi/web/openssl
    ./build-openssl.sh
    popd

    mkdir -p web-build && pushd web-build
    emcmake cmake .. -D${BUILD_ARG} \
          -DPEACEMAKR_BUILD_WEB=ON -DPEACEMAKR_STATIC_BUILD=OFF -DASAN=OFF \
          -DOPENSSL_ROOT_DIR=../src/ffi/web/openssl/build \
          -DOPENSSL_CRYPTO_LIBRARY=../src/ffi/web/openssl/build/lib/libcrypto.a \
          -DOPENSSL_SSL_LIBRARY=../src/ffi/web/openssl/build/lib/libssl.a \
          -DOPENSSL_INCLUDE_DIR=../src/ffi/web/openssl/build/include/

    emmake make peacemakr-core-crypto corecrypto_js
    cp src/ffi/web/corecrypto.js "${out_dir}"
    cp src/ffi/web/corecrypto.wasm "${out_dir}"
}

BUILD_ARG="CMAKE_BUILD_TYPE=DEBUG"

if [[ "${2}" == "release" ]]; then
    BUILD_ARG="CMAKE_BUILD_TYPE=RELEASE"
fi

get_crypto_file ${1}