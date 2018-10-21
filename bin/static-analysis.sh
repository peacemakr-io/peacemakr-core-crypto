#!/usr/bin/env bash

pushd ..
if [ -d "cmake-build-debug" ]; then
    cd cmake-build-debug;
elif [ -d "build" ]; then
    cd build;
fi
rm -rf CMakeFiles/ CMakeCache.txt;
scan-build cmake .. -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl@1.1
scan-build make
popd