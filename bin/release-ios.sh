#!/usr/bin/env bash

set -ex

function usage {
    echo "Usage: ./release-ios.sh [path to peacemakr-ios folder] [optional: first]"
    echo "for example, ./bin/release-ios.sh ~/peacemakr/peacemakr-ios-sdk first"
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
    pushd src/ffi/swift/openssl
    ./build-openssl.sh
    popd
fi

mkdir -p ios-build

pushd ios-build
cmake .. -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl@1.1 -DOPENSSL_LIBRARIES=/usr/local/opt/openssl@1.1/lib -DPEACEMAKR_BUILD_IOS=ON -DCMAKE_INSTALL_PREFIX=../src/ffi/swift/libCoreCrypto
make install
popd

pushd ${PROJECT_SRC}/src/ffi/swift/libCoreCrypto
sh build-core-crypto.sh
popd

pushd ${PROJECT_SRC}/src/ffi/swift/CoreCrypto
xcodebuild -project CoreCrypto.xcodeproj -scheme CoreCrypto -sdk iphonesimulator -destination 'platform=iOS Simulator,name=iPhone 8,OS=13.3' test
xcodebuild -project CoreCrypto.xcodeproj ONLY_ACTIVE_ARCH=NO -configuration Release -miphoneos-version-min=8.1 -sdk iphoneos build
xcodebuild -project CoreCrypto.xcodeproj ONLY_ACTIVE_ARCH=NO -configuration Release -miphoneos-version-min=8.1 -sdk iphonesimulator build
popd

mkdir -p ${OUTPUT_DIR}
pushd ${OUTPUT_DIR}
rm -rf CoreCrypto.framework || true
cp -R ${PROJECT_SRC}/src/ffi/swift/CoreCrypto/build/Release-iphoneos/CoreCrypto.framework .
cp ${PROJECT_SRC}/src/ffi/swift/CoreCrypto/build/Release-iphonesimulator/CoreCrypto.framework/Modules/CoreCrypto.swiftmodule/* ${OUTPUT_DIR}/CoreCrypto.framework/Modules/CoreCrypto.swiftmodule
defaults write ${OUTPUT_DIR}/CoreCrypto.framework/Info.plist CFBundleSupportedPlatforms -array-add "iPhoneSimulator"
lipo -create -output "CoreCrypto.framework/CoreCrypto" "${PROJECT_SRC}/src/ffi/swift/CoreCrypto/build/Release-iphoneos/CoreCrypto.framework/CoreCrypto" "${PROJECT_SRC}/src/ffi/swift/CoreCrypto/build/Release-iphonesimulator/CoreCrypto.framework/CoreCrypto"

# copy debug info
cp -R ${PROJECT_SRC}/src/ffi/swift/CoreCrypto/build/Release-iphoneos/CoreCrypto.framework.dSYM .
lipo -create -output "CoreCrypto.framework.dSYM/Contents/Resources/DWARF/CoreCrypto" "${PROJECT_SRC}/src/ffi/swift/CoreCrypto/build/Release-iphoneos/CoreCrypto.framework.dSYM/Contents/Resources/DWARF/CoreCrypto" "${PROJECT_SRC}/src/ffi/swift/CoreCrypto/build/Release-iphonesimulator/CoreCrypto.framework.dSYM/Contents/Resources/DWARF/CoreCrypto"

rm -rf ${PROJECT_SRC}/src/ffi/swift/CoreCrypto/build
popd

popd
