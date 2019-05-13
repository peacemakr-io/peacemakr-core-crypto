#!/bin/sh

if [[ -z "${ANDROID_NDK_ROOT}" ]]; then
    echo "Must define ANDROID_NDK_ROOT"
    exit 128
fi

OPENSSL_VERSION=1.1.1b
ANDROID_API_LEVEL=21

OUT_DIR=$(pwd)/openssl-build

BUILD_TARGETS="armeabi-v7a arm64-v8a x86 x86_64"

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

PLATFORM='unknown'
unamestr=$(uname)
if [[ "$unamestr" == 'Linux' ]]; then
   PLATFORM='linux'
elif [[ "$unamestr" == 'Darwin' ]]; then
   PLATFORM='darwin'
fi

BASE_OPTIONS="no-asm no-ssl3 no-comp no-hw no-engine no-async CC=clang"
BINDIR="${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/${PLATFORM}-x86_64"
MAKE_CC="${BINDIR}/bin/clang"
MAKE_CXX="${BINDIR}/bin/clang++"
MAKE_AR="${BINDIR}/bin/llvm-ar"


###### build-function #####
build_the_thing() {
    ANDROID_NDK=${ANDROID_NDK_ROOT} \
    PATH=${BINDIR}/bin:${PATH} \
    ./Configure ${SSL_TARGET} ${OPTIONS}

    make clean

    ANDROID_NDK=${ANDROID_NDK_ROOT} \
    PATH=${BINDIR}/bin:${PATH} \
    make CC=${MAKE_CC} CXX=${MAKE_CXX} AR=${MAKE_AR}

    ANDROID_NDK=${ANDROID_NDK_ROOT} \
    PATH=${BINDIR}/bin:${PATH} \
    make CC=${MAKE_CC} CXX=${MAKE_CXX} AR=${MAKE_AR} install_sw DESTDIR=${BINDIR} || exit 128
}

###### set variables according to build-target #####
for build_target in ${BUILD_TARGETS}
do
    case ${build_target} in
    armeabi)
        TRIBLE="arm-linux-androideabi"
        TC_NAME="arm-linux-androideabi-4.9"
        OPTIONS="--target=armv5te-linux-androideabi -mthumb -fPIC -latomic -D__ANDROID_API__=$ANDROID_API_LEVEL ${BASE_OPTIONS}"
        ARCH="arm"
        SSL_TARGET="android-arm"
    ;;
    armeabi-v7a)
        TRIBLE="arm-linux-androideabi"
        TC_NAME="arm-linux-androideabi-4.9"
        OPTIONS="--target=armv7a-linux-androideabi -Wl,--fix-cortex-a8 -fPIC -D__ANDROID_API__=$ANDROID_API_LEVEL ${BASE_OPTIONS}"
        ARCH="arm"
        SSL_TARGET="android-arm"
    ;;
    x86)
        TRIBLE="i686-linux-android"
        TC_NAME="x86-4.9"
        OPTIONS="-fPIC -D__ANDROID_API__=${ANDROID_API_LEVEL} ${BASE_OPTIONS}"
        ARCH="x86"
        SSL_TARGET="android-x86"
    ;;
    x86_64)
        TRIBLE="x86_64-linux-android"
        TC_NAME="x86_64-4.9"
        OPTIONS="-fPIC -D__ANDROID_API__=${ANDROID_API_LEVEL} ${BASE_OPTIONS}"
        ARCH="x86_64"
        SSL_TARGET="android-x86_64"
    ;;
    arm64-v8a)
        TRIBLE="aarch64-linux-android"
        TC_NAME="aarch64-linux-android-4.9"
        OPTIONS="-fPIC -D__ANDROID_API__=${ANDROID_API_LEVEL} ${BASE_OPTIONS}"
        ARCH="arm64"
        SSL_TARGET="android-arm64"
    ;;
    esac

    build_the_thing
#### copy libraries and includes to output-directory #####
    mkdir -p ${OUT_DIR}/${build_target}/include
    cp -R ${BINDIR}/usr/local/include/* ${OUT_DIR}/${build_target}/include
    mkdir -p ${OUT_DIR}/${build_target}/lib
    cp -R ${BINDIR}/usr/local/lib/* ${OUT_DIR}/${build_target}/lib

    echo "Successfully built for target ${build_target}"
done