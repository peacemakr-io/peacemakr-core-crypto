#!/bin/bash

set -ex

#
# Build the JNI C headers.
#
javac -h src/main/c/. src/main/java/io/peacemakr/corecrypto/*.java src/main/java/cz/adamh/utils/*.java

#
# Build the JNI Glue.
#
mkdir -p bin/main/c
gcc -I${JAVA_HOME}/include -I${JAVA_HOME}/include/linux -I${JAVA_HOME}/include/darwin -c src/main/c/io_peacemakr_corecrypto_Crypto.c -o bin/main/c/io_peacemakr_corecrypto_Crypto.o
ar rcs bin/main/c/libpeacemakr-core-crypto-jni.a bin/main/c/*.o

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
jar cfm ../../../bin/main/java/PeacemakrCoreCrypto.jar Manifest.txt io/peacemakr/corecrypto/*.class
cd ../../..
cd bin/main/c
jar -uf ../../../bin/main/java/PeacemakrCoreCrypto.jar libpeacemakr-core-crypto-jni.a
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