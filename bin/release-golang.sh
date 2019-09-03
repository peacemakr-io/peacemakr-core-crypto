#!/usr/bin/env bash

set -ex

function usage {
    echo "Usage: ./bin/release-golang.sh [path to peacemakr-api folder] [optional: release]"
    echo "for example, ./bin/release-golang.sh ~/peacemakr/peacemakr-api release"
}

if [[ "$#" -gt 2 ]]; then
    echo "Illegal use"
    usage
    exit 1
fi

function get_crypto_file_linux {
    out_dir=${1}

    docker run corecrypto:latest tar -czvf - -C /go/src peacemakr > "${out_dir}/peacemakr-core-crypto-go-musl.tar.gz"
}

function get_crypto_file_mac {
    out_dir=${1}
    build_type=${2}

    mkdir -p /tmp/peacemakr/crypto/include/openssl
    mkdir -p build
    pushd build
    cmake .. -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl@1.1 -D${build_type} -DCMAKE_INSTALL_PREFIX=/tmp/peacemakr/crypto
    make check install
    cp -R /usr/local/opt/openssl@1.1/include/openssl /tmp/peacemakr/crypto/include/
    cp -R ../src/ffi/go/src/peacemakr/crypto/ /tmp/peacemakr/crypto/
    tar -czvf ${out_dir}/peacemakr-core-crypto-go-macos.tar.gz -C /tmp peacemakr
    popd
    rm -rf /tmp/peacemakr
}

BUILD_ARG="CMAKE_BUILD_TYPE=DEBUG"

if [[ "${2}" == "release" ]]; then
    BUILD_ARG="CMAKE_BUILD_TYPE=RELEASE"
fi

docker build -t corecrypto-dependencies:latest . -f docker/go-dependencies.Dockerfile --build-arg=${BUILD_ARG}
docker build -t corecrypto:latest . -f docker/go.Dockerfile --build-arg=${BUILD_ARG}
get_crypto_file_linux ${1}
get_crypto_file_mac ${1} ${BUILD_ARG}

pushd "${1}"
rm -rf crypto/*
tar -xzvf peacemakr-core-crypto-go-macos.tar.gz
cp -R peacemakr/crypto ./
tar -xzvf peacemakr-core-crypto-go-musl.tar.gz
cp peacemakr/crypto/lib/*.so ./crypto/lib
rm -rf crypto/lib/cmake
rm -rf peacemakr peacemakr-core-crypto-go-macos.tar.gz peacemakr-core-crypto-go-musl.tar.gz
echo "package keeplib" > crypto/lib/keep.go
echo "package keeppeacemakr" > crypto/include/peacemakr/keep.go
echo "package keepopenssl" > crypto/include/openssl/keep.go
popd
