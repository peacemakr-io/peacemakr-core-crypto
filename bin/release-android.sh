#!/usr/bin/env bash

set -ex

function usage {
    echo "Usage: ANDROID_NDK_ROOT=/path/to/ndk-bundle ./release-android.sh"
}

if [[ "$#" -gt 2 ]]; then
    echo "Illegal use"
    usage
    exit 1
fi

if [[ -z "${1}" ]]; then
    echo "Illegal use"
    usage
    exit 1
fi

OUTPUT_DIR=${1}

pushd ..

PROJECT_SRC=$(pwd)

if [[ ! -z "${2}" ]]; then
    pushd src/ffi/android/openssl
    ./build-openssl.sh
    popd
fi

mkdir -p ${OUTPUT_DIR}
pushd ${OUTPUT_DIR}
# TODO: copy stuff over to OUTPUT_DIR
popd