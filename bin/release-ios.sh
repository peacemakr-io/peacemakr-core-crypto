#!/usr/bin/env bash

mkdir -p build && cd build
cmake .. -DPEACEMAKR_BUILD_IOS=ON
