#!/bin/bash

set -ex

#
# Build the JNI C headers.
#
javac -h src/main/c/. src/main/java/io/peacemakr/corecrypto/*.java

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
javac src/main/java/io/peacemakr/corecrypto/*.java
jar cf bin/main/java/PeacemakrCoreCrypto.jar src/main/java/io/peacemakr/corecrypto/*.class
