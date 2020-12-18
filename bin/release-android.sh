#!/usr/bin/env bash

set -ex

function usage {
    echo "Usage: ANDROID_NDK_ROOT=/path/to/ndk-bundle ./release-android.sh [path to peacemakr-android folder] [optional: first]"
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

if [[ ! -z "${2}" ]]; then
    pushd src/ffi/java/openssl
    ./build-openssl.sh
    popd
fi

cd src/ffi/java
# gradle's jar target will run the tests before creating the jar
if [[ "${2}" == "release" ]]; then
    ./gradlew android:clean android:bundleReleaseAar
    cp android/build/outputs/aar/android-release.aar ${1}
else
    ./gradlew android:clean android:bundleDebugAar
    cp android/build/outputs/aar/android-debug.aar ${1}
fi
cd ../../..
