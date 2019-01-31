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

function get_crypto_file {

    out_dir=${1}

    docker run corecrypto:latest cat /go/src/peacemakr/crypto/crypto.go > ${out_dir}/src/peacemakr/crypto/crypto.go
    docker run corecrypto:latest cat /go/src/peacemakr/crypto/crypto_test.go > ${out_dir}/src/peacemakr/crypto/crypto_test.go
    docker run corecrypto:latest cat /usr/local/include/peacemakr/crypto.h > ${out_dir}/include/peacemakr/crypto.h
    docker run corecrypto:latest cat /usr/local/include/peacemakr/random.h > ${out_dir}/include/peacemakr/random.h

}

BUILD_ARG="CMAKE_BUILD_TYPE=DEBUG"

if [[ "${2}" == "release" ]]; then
    BUILD_ARG="CMAKE_BUILD_TYPE=RELEASE"
fi

docker build -t corecrypto-dependencies:latest . -f docker/go-dependencies.Dockerfile --build-arg=${BUILD_ARG}
docker build -t corecrypto:latest . -f docker/go.Dockerfile --build-arg=${BUILD_ARG}
get_crypto_file ${1}

# Setup aws credentials
`aws ecr get-login --no-include-email --region us-east-2 --profile peacemakr` || true

# Release to ECR
docker tag corecrypto-dependencies:latest 716293438869.dkr.ecr.us-east-2.amazonaws.com/corecrypto-dependencies:latest
docker push 716293438869.dkr.ecr.us-east-2.amazonaws.com/corecrypto-dependencies:latest

docker tag corecrypto:latest 716293438869.dkr.ecr.us-east-2.amazonaws.com/corecrypto:latest
docker push 716293438869.dkr.ecr.us-east-2.amazonaws.com/corecrypto:latest

