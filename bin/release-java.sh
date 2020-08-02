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
# gradle's jar target will run the tests before creating the jar
if [[ "${2}" == "release" ]]; then
    ./gradlew java:clean java:jar -Prelease
else
    ./gradlew java:clean java:jar
fi
cd ../../..

#
# Make it obvious where the artifact is.
#
cp src/ffi/java/java/build/libs/*.jar ${1}
