#!/usr/bin/env bash

set -ex

if [ $# -eq 0 ]; then
    OUTPUT_DIR=src/ffi/swift/CoreCrypto/universal
else
    OUTPUT_DIR=$1
fi

pushd ..

PROJECT_SRC=$(pwd)

#pushd src/ffi/swift/openssl
#./build-openssl.sh
#popd

mkdir -p ios-build

pushd ios-build
cmake .. -DPEACEMAKR_BUILD_CPP=OFF -DPEACEMAKR_BUILD_GO=OFF -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl@1.1 -DOPENSSL_LIBRARIES=/usr/local/opt/openssl@1.1/lib -DPEACEMAKR_BUILD_IOS=ON -DCMAKE_INSTALL_PREFIX=../src/ffi/swift/libCoreCrypto
make install
popd

pushd ${PROJECT_SRC}/src/ffi/swift/libCoreCrypto
sh build-core-crypto.sh
popd

pushd ${PROJECT_SRC}/src/ffi/swift/CoreCrypto
xcodebuild -project CoreCrypto.xcodeproj -scheme CoreCrypto -sdk iphonesimulator -destination 'platform=iOS Simulator,name=iPhone 6,OS=12.2' test
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
