#!/usr/bin/env bash

set -ex

pushd ..
mkdir -p ios-build
pushd ios-build
cmake .. -DPEACEMAKR_BUILD_CPP=OFF -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl@1.1 -DOPENSSL_LIBRARIES=/usr/local/opt/openssl@1.1/lib -DPEACEMAKR_BUILD_IOS=ON -DCMAKE_INSTALL_PREFIX=../src/ffi/swift/libCoreCrypto
make install
popd
pushd src/ffi/swift/libCoreCrypto
sh build-core-crypto.sh
popd
popd
