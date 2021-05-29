#!/usr/bin/env bash

set -ex

INSTALL_DIR=$(pwd)/build
mkdir -p ${INSTALL_DIR}
mkdir -p ${INSTALL_DIR}/include
mkdir -p ${INSTALL_DIR}/lib

OPENSSL_VERSION=1.1.1k

if [[ ! -f "openssl-${OPENSSL_VERSION}.tar.gz" ]]; then
    curl -O https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz
fi

if [[ ! -d "openssl-${OPENSSL_VERSION}" ]]; then
  tar -xzf openssl-${OPENSSL_VERSION}.tar.gz
fi

pushd openssl-${OPENSSL_VERSION}

CC=emcc CXX=em++ AR=emar RANLIB=emranlib ./Configure linux-generic32 \
      no-asm \
      no-err \
      no-ssl2 \
      no-ssl3 \
      no-threads \
      no-engine \
      no-hw \
      no-weak-ssl-ciphers \
      no-dtls \
      no-shared \
      no-dso \
      -D__STDC_NO_ATOMICS__=1 -DNO_FORK -DPEDANTIC -Oz \
      --prefix=${INSTALL_DIR}

sed 's/^CROSS_COMPILE.*$/CROSS_COMPILE=/g' Makefile

emmake make -j build_generated libssl.a libcrypto.a
rm -rf ${INSTALL_DIR}/include/* ${INSTALL_DIR}/lib/*
cp -R include/openssl ${INSTALL_DIR}/include
cp libcrypto.a ${INSTALL_DIR}/lib/
cp libssl.a ${INSTALL_DIR}/lib/
popd
