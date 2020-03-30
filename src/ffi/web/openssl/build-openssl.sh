#!/usr/bin/env bash

set -ex

if [[ ! -z "${EMSDK}" ]]; then
    . ${EMSDK}/emsdk_set_env.sh
elif [[ -f ~/.emscripten ]]; then
    echo "Emscripten already set-up"
else
    echo "Must define EMSDK environment variable"
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

emconfigure ./Configure linux-generic64 no-asm no-ssl3 no-comp no-hw no-engine no-async -static -D__STDC_NO_ATOMICS__ --prefix=${INSTALL_DIR}

sed -i 's/^CROSS_COMPILE.*$/CROSS_COMPILE=/g' Makefile

emmake make -j build_generated libssl.a libcrypto.a
rm -rf ${INSTALL_DIR}/include/* ${INSTALL_DIR}/lib/*
cp -R include/openssl ${INSTALL_DIR}/include
cp libcrypto.a ${INSTALL_DIR}/lib/
cp libssl.a ${INSTALL_DIR}/lib/
popd
