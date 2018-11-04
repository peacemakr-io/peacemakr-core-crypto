#!/usr/bin/env bash

set -ex

pushd ..

pushd src/ffi/swift/openssl
./build-openssl.sh
popd

mkdir -p ios-build

pushd ios-build
cmake .. -DPEACEMAKR_BUILD_CPP=OFF -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl@1.1 -DOPENSSL_LIBRARIES=/usr/local/opt/openssl@1.1/lib -DPEACEMAKR_BUILD_IOS=ON -DCMAKE_INSTALL_PREFIX=../src/ffi/swift/libCoreCrypto
make install
popd

pushd src/ffi/swift/libCoreCrypto
sh build-core-crypto.sh
popd

pushd src/ffi/swift/CoreCrypto
#xcodebuild -project CoreCrypto.xcodeproj -scheme CoreCrypto -sdk iphonesimulator -destination 'platform=iOS Simulator,name=iPhone 6,OS=12.1' test
xcodebuild -project CoreCrypto.xcodeproj ONLY_ACTIVE_ARCH=NO -configuration Release -miphoneos-version-min=8.1 -sdk iphoneos build
xcodebuild -project CoreCrypto.xcodeproj ONLY_ACTIVE_ARCH=NO -configuration Release -miphoneos-version-min=8.1 -sdk iphonesimulator build
popd

mkdir -p src/ffi/swift/CoreCrypto/universal
pushd src/ffi/swift/CoreCrypto/universal
rm -rf CoreCrypto.framework || true
cp -R ../build/Release-iphoneos/CoreCrypto.framework .
cp ../build/Release-iphonesimulator/CoreCrypto.framework/Modules/CoreCrypto.swiftmodule/* CoreCrypto.framework/Modules/CoreCrypto.swiftmodule
defaults write $(pwd)/CoreCrypto.framework/Info.plist CFBundleSupportedPlatforms -array-add "iPhoneSimulator"
lipo -create -output "CoreCrypto.framework/CoreCrypto" "../build/Release-iphoneos/CoreCrypto.framework/CoreCrypto" "../build/Release-iphonesimulator/CoreCrypto.framework/CoreCrypto"

# copy debug info
cp -R ../build/Release-iphoneos/CoreCrypto.framework.dSYM .
lipo -create -output "CoreCrypto.framework.dSYM/Contents/Resources/DWARF/CoreCrypto" "../build/Release-iphoneos/CoreCrypto.framework.dSYM/Contents/Resources/DWARF/CoreCrypto" "../build/Release-iphonesimulator/CoreCrypto.framework.dSYM/Contents/Resources/DWARF/CoreCrypto"

rm -rf ../build
popd

popd
