#!/bin/bash

#
# Visibility + stop on errors
#
set -ex

#
# Cleanup crap from previous builds
#
rm -rf src/ffi/java/bin/main/java || true
rm -rf *.jar || true

#
# Actually build it.
#
cd src/ffi/java
./build-jni.sh $@
cd ../../..

#
# Make it obvious where the artifact is.
#
cp src/ffi/java/bin/main/java/*.jar .
