#!/usr/bin/env bash

set -ex

function usage {
    echo "Usage: ./bin/release-golang.sh [path to include folder] [path to go root]"
    echo "for example, ./bin/release-golang.sh ../peacemakr-api/include/ ../peacemakr-api/"
}

if [ "$#" -ne 2 ]; then
    echo "Illegal use"
    usage
    exit 1
fi

function get_crypto_file {

    h_dir=${1}
    go_root=${2}

    docker rm src-container || true
    IMG_ID=$(docker run --name src-container -d go-builder sh)
    docker cp src-container:/go/src/peacemakr/crypto/crypto.go ${go_root}/src/peacemakr/crypto/crypto.go
    docker cp src-container:/go/src/peacemakr/crypto/crypto_test.go ${go_root}/src/peacemakr/crypto/crypto_test.go
    docker cp src-container:/usr/local/include/peacemakr/crypto.h ${h_dir}/peacemakr/crypto.h
    docker cp src-container:/usr/local/include/peacemakr/random.h ${h_dir}/peacemakr/random.h
    docker kill ${IMG_ID} || true
}

docker build -t go-builder . -f docker/go.Dockerfile
get_crypto_file ${1} ${2}
