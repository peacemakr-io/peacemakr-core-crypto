#!/usr/bin/env bash

set -ex

function usage {
    echo "Usage: ./bin/release-web.sh [path to peacemakr-api folder] [optional: release]"
    echo "for example, ./bin/release-web.sh ~/peacemakr/peacemakr-js release"
}

if [[ "$#" -gt 2 ]]; then
    echo "Illegal use"
    usage
    exit 1
fi

function get_crypto_file {

    out_dir=${1}

    docker run corecrypto-wasm:latest cat /opt/corecrypto-build/lib/corecrypto.js > ${out_dir}/corecrypto.js
    docker run corecrypto-wasm:latest cat /opt/corecrypto-build/lib/corecrypto.wasm > ${out_dir}/corecrypto.wasm
}

BUILD_ARG="CMAKE_BUILD_TYPE=DEBUG"

if [[ "${2}" == "release" ]]; then
    BUILD_ARG="CMAKE_BUILD_TYPE=RELEASE"
fi

docker build -t corecrypto-wasm:latest . -f docker/wasm.Dockerfile --build-arg=${BUILD_ARG}
get_crypto_file ${1}