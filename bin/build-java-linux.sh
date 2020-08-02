#!/bin/bash

set -e

BUILD_ARG="BUILD_TYPE=debug"

if [[ "${1}" == "release" ]]; then
    BUILD_ARG="BUILD_TYPE=release"
fi

CONTAINER_PATH=/opt/src/ffi/java/java/src/main/resources/lib/
LOCAL_PATH=$(pwd)/src/ffi/java/java/src/main/resources/lib

# Just in case the path doesn't exist
mkdir -p "${LOCAL_PATH}"

docker build -t java-env . -f docker/java.Dockerfile --build-arg=${BUILD_ARG}
docker run java-env tar cvf - -C ${CONTAINER_PATH} libpeacemakr-core-crypto.so libpeacemakr-core-crypto-jni.so | tar xvf - -C "${LOCAL_PATH}"
