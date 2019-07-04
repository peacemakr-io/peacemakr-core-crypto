#!/usr/bin/env bash

set -ex

if [[ ! -z "${EMSCRIPTEN_SDK}" ]]; then
    . ${EMSCRIPTEN_SDK}/emsdk_env.sh
elif [[ -f ~/.emscripten ]]; then
    echo "Emscripten already set-up"
else
    echo "Must define EMSCRIPTEN_SDK environment variable"
    exit 1
fi

INSTALL_DIR=$(pwd)/build
mkdir -p ${INSTALL_DIR}
mkdir -p ${INSTALL_DIR}/include
mkdir -p ${INSTALL_DIR}/lib

OPENSSL_VERSION=1.1.1b

if [[ ! -d "openssl-${OPENSSL_VERSION}" ]]; then
    curl -O https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz
    tar -xzf openssl-${OPENSSL_VERSION}.tar.gz
fi

pushd openssl-${OPENSSL_VERSION}

CC=emcc CXX=em++ AR=emar RANLIB=emranlib ./Configure linux-generic64 no-asm no-ssl3 no-comp no-hw no-engine no-async -D__STDC_NO_ATOMICS__ --prefix=${INSTALL_DIR}

sed 's/^CROSS_COMPILE.*$/CROSS_COMPILE=/g' Makefile

emmake make -j build_generated libssl.a libcrypto.a
rm -rf ${INSTALL_DIR}/include/* ${INSTALL_DIR}/lib/*
cp -R include/openssl ${INSTALL_DIR}/include
cp libcrypto.a ${INSTALL_DIR}/lib/
cp libssl.a ${INSTALL_DIR}/lib/
popd
