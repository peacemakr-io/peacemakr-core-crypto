#!/bin/bash

#
# Visibility + stop on errors
#
set -ex

#
# Cleanup crap from previous builds
#
rm -rf src/ffi/java/build || true
rm -rf *.jar || true

#
# Actually build it.
#
cd src/ffi/java
./gradlew test
if [[ "${2}" == "release" ]]; then
    ./gradlew jar -Prelease=true
else
    ./gradlew jar
fi
cd ../../..

#
# Make it obvious where the artifact is.
#
cp src/ffi/java/build/libs/*.jar ${1}
