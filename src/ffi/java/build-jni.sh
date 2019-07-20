#!/bin/bash

set -ex

#
# Build the JNI C headers.
#
javac -h src/main/c/. src/main/java/io/peacemakr/corecrypto/*.java src/main/java/cz/adamh/utils/*.java

#
# Build the JNI Glue.
#
mkdir -p bin/main/c && pushd bin/main/c
cmake ../../../../../.. -DCMAKE_INSTALL_PREFIX=$(pwd) -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl@1.1 -DPEACEMAKR_BUILD_JAVA=ON
make install
popd
# mkdir -p bin/main/c
# gcc -I${JAVA_HOME}/include -I${JAVA_HOME}/include/linux -I${JAVA_HOME}/include/darwin -c src/main/c/*.c
# ar rcs bin/main/c/libpeacemakr-core-crypto-jni.a bin/main/c/*.o

#
# Mac dylib
#
g++ -dynamiclib bin/main/c/*.o -o bin/main/c/libpeacemakr-core-crypto-jni.dylib

#
# Linux .so
#
gcc -shared -o bin/main/c/libpeacemakr-core-crypto-jni.so -fPIC bin/main/c/*.o

#
# Compile the Java interface
#
mkdir -p bin/main/java
javac src/main/java/io/peacemakr/corecrypto/*.java src/main/java/cz/adamh/utils/*.java
cd src/main/java
echo """
Name: corecrypto
Specification-Title: Peacemakr Core Crypto Library
Specification-Version: 1.0
Specification-Vendor: Peacemakr Crypto Systems
Implementation-Title: io.peacemakr.corecrypto
Implementation-Version: 0
Implementation-Vendor: Peacemakr Crypto Systems
""" > Manifest.txt
jar cfm ../../../bin/main/java/PeacemakrCoreCrypto.jar Manifest.txt io/peacemakr/corecrypto/*.class cz/adamh/utils/*.class
cd ../../..
cd bin/main/c
jar -uf ../../../bin/main/java/PeacemakrCoreCrypto.jar lib/libpeacemakr-core-crypto-jni.*
jar -uf ../../../bin/main/java/PeacemakrCoreCrypto.jar lib/libpeacemakr-core-crypto.*
cd ../../..
jar tf bin/main/java/PeacemakrCoreCrypto.jar

#
# Version this?
#
if [ "$1" == "-release" ]; then
  TAG="latest"
  if [[ ! -z "${2}" ]]; then
    TAG=${2}
  fi

  mv bin/main/java/PeacemakrCoreCrypto.jar bin/main/java/PeacemakrCoreCrypto-${TAG}.jar

fi
