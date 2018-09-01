#!/usr/bin/env bash

set -ex

function usage {
    echo "Usage: ./bin/release-golang.sh [profile] [path to include folder] [path to go root] [version]"
    echo "for example, ./bin/release-golang.sh peacemakr ../peacemakr-api/include/ ../peacemakr-api/ 0.0.4"
}

if [ "$#" -ne 4 ]; then
    echo "Illegal use"
    usage
    exit 1
fi

function get_crypto_file {

    h_dir=${1}
    go_root=${2}
    version=${3}

    docker rm src-container || true
    IMG_ID=$(docker run --name src-container -d peacemakr-core-crypto:${version} sh)
    docker cp src-container:/go/src/peacemakr/crypto/crypto.go ${go_root}/src/peacemakr/crypto/crypto.go
    docker cp src-container:/go/src/peacemakr/crypto/crypto_test.go ${go_root}/src/peacemakr/crypto/crypto_test.go
    docker cp src-container:/usr/local/include/peacemakr/crypto.h ${h_dir}/peacemakr/crypto.h
    docker cp src-container:/usr/local/include/peacemakr/random.h ${h_dir}/peacemakr/random.h
    docker kill ${IMG_ID} || true
}

export AWS_PROFILE=${1}
aws ecr get-login --no-include-email | sh
docker build -t peacemakr-core-crypto:${4} . -f docker/go.Dockerfile
docker tag peacemakr-core-crypto:${4} 716293438869.dkr.ecr.us-east-2.amazonaws.com/peacemakr-core-crypto:${4}
docker push 716293438869.dkr.ecr.us-east-2.amazonaws.com/peacemakr-core-crypto:${4}
get_crypto_file ${2} ${3} ${4}
