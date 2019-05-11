#!/bin/sh

if [[ -z "${ANDROID_NDK_ROOT}" ]]; then
    echo "Must define ANDROID_NDK_ROOT"
    exit 128
fi

OPENSSL_VERSION=1.1.1b
ANDROID_API_LEVEL=21

BUILD_DIR=/tmp/openssl_android_build
OUT_DIR=$(pwd)/openssl-build

BUILD_TARGETS="armeabi armeabi-v7a arm64-v8a x86 x86_64"

if [[ ! -d openssl-${OPENSSL_VERSION} ]]
then
    if [[ ! -f openssl-${OPENSSL_VERSION}.tar.gz ]]
    then
        wget https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz || exit 128
    fi
    tar xzf openssl-${OPENSSL_VERSION}.tar.gz || exit 128
fi

cd openssl-${OPENSSL_VERSION} || exit 128

###### remove output-directory #####
rm -rf ${OUT_DIR}

BASE_OPTIONS="no-asm no-ssl3 no-comp no-hw no-engine no-async"

###### build-function #####
build_the_thing() {
    ${ANDROID_NDK_ROOT}/build/tools/make_standalone_toolchain.py --install-dir=${DESTDIR} --arch=${ARCH} --api=${ANDROID_API_LEVEL}

    ANDROID_NDK=${DESTDIR} \
    PATH=${DESTDIR}/bin:${PATH} \
    ./Configure ${SSL_TARGET} ${OPTIONS}

    make clean

    ANDROID_NDK=${DESTDIR} \
    PATH=${DESTDIR}/bin:${PATH} \
    make

    ANDROID_NDK=${DESTDIR} \
    PATH=${DESTDIR}/bin:${PATH} \
    make install_sw DESTDIR=${DESTDIR} || exit 128
}

###### set variables according to build-target #####
for build_target in ${BUILD_TARGETS}
do
    case ${build_target} in
    armeabi)
        TRIBLE="arm-linux-androideabi"
        TC_NAME="arm-linux-androideabi-4.9"
        OPTIONS="--target=armv5te-linux-androideabi -mthumb -fPIC -latomic -D__ANDROID_API__=$ANDROID_API_LEVEL ${BASE_OPTIONS}"
        DESTDIR="$BUILD_DIR/armeabi"
        ARCH="arm"
        SSL_TARGET="android-arm"
    ;;
    armeabi-v7a)
        TRIBLE="arm-linux-androideabi"
        TC_NAME="arm-linux-androideabi-4.9"
        OPTIONS="--target=armv7a-linux-androideabi -Wl,--fix-cortex-a8 -fPIC -D__ANDROID_API__=$ANDROID_API_LEVEL ${BASE_OPTIONS}"
        DESTDIR="$BUILD_DIR/armeabi-v7a"
        ARCH="arm"
        SSL_TARGET="android-arm"
    ;;
    x86)
        TRIBLE="i686-linux-android"
        TC_NAME="x86-4.9"
        OPTIONS="-fPIC -D__ANDROID_API__=${ANDROID_API_LEVEL} ${BASE_OPTIONS}"
        DESTDIR="$BUILD_DIR/x86"
        ARCH="x86"
        SSL_TARGET="android-x86"
    ;;
    x86_64)
        TRIBLE="x86_64-linux-android"
        TC_NAME="x86_64-4.9"
        OPTIONS="-fPIC -D__ANDROID_API__=${ANDROID_API_LEVEL} ${BASE_OPTIONS}"
        DESTDIR="$BUILD_DIR/x86_64"
        ARCH="x86_64"
        SSL_TARGET="android-x86_64"
    ;;
    arm64-v8a)
        TRIBLE="aarch64-linux-android"
        TC_NAME="aarch64-linux-android-4.9"
        OPTIONS="-fPIC -D__ANDROID_API__=${ANDROID_API_LEVEL} ${BASE_OPTIONS}"
        DESTDIR="$BUILD_DIR/arm64-v8a"
        ARCH="arm64"
        SSL_TARGET="android-arm64"
    ;;
    esac

    rm -rf ${DESTDIR}
    build_the_thing
#### copy libraries and includes to output-directory #####
    mkdir -p ${OUT_DIR}/${build_target}/include
    cp -R ${DESTDIR}/usr/local/include/* ${OUT_DIR}/${build_target}/include
    mkdir -p ${OUT_DIR}/${build_target}/lib
    cp -R ${DESTDIR}/usr/local/lib/* ${OUT_DIR}/${build_target}/lib

    echo "Successfully built for target ${build_target}"
done