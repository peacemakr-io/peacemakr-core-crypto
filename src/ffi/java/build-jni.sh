#!/bin/sh

set -ex

#
# Build the JNI C headers.
#
#javac -h src/main/c/. src/main/java/io/peacemakr/corecrypto/*.java src/main/java/cz/adamh/utils/*.java

#
# Build the JNI Glue.
#
mkdir -p bin/main/c && cd bin/main/c
cmake ../../../../../.. -DCMAKE_INSTALL_PREFIX=$(pwd) -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl@1.1 -DPEACEMAKR_BUILD_JAVA=ON
make install
cd ../../..

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
chmod -R 755 lib/*
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
