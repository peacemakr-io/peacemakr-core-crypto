#!/usr/bin/env bash

set -e

function usage {
    echo "Usage: ./release-golang.sh OPTIONS"
    echo "Options: "
    echo "  -o <path-to-file-output>"
}

function get_crypto_file {

    FILE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

    output_dir=${FILE_DIR}/../src/ffi/go/src/peacemakr/crypto/

    while getopts "o:h" o; do
    case "${o}" in
        o) output_dir=${OPTARG}
           ;;
        h) usage
        esac
    done
    shift $((OPTIND-1))

    pushd ${FILE_DIR}/..
    docker build -t go-builder . -f docker/go.Dockerfile
    IMG_ID=$(docker run --name src-container -d go-builder sh)
    docker cp src-container:/go/src/peacemakr/crypto/crypto.go ${output_dir}
    docker kill ${IMG_ID}
}

get_crypto_file "$@"
