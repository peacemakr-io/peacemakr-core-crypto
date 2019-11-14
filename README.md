# peacemakr-core-crypto
[![CircleCI](https://circleci.com/gh/notasecret/peacemakr-core-crypto/tree/master.svg?style=svg&circle-token=a5e0dd516384638b6e97cd79c7963d8081873df2)](https://circleci.com/gh/notasecret/peacemakr-core-crypto/tree/master)

## About
This package defines the core crypto functionality for peacemakr.

## Documentation
From the repository base directory,
`./bin/serve-docs.sh` will set up a docker image that serves the doxygen docs on `localhost:3000`

## Make sure you have OpenSSL 1.1 or greater installed:
### On Mac:
`brew install openssl@1.1`

### On Debian distros (tried on Ubuntu 18.04 and debian10)
On debian distros the maximum version that apt getable is 1.0.x, so you need to manually install. 
Go to `https://www.openssl.org/source/` and download the tar.gz

Then run the following to install the package:
`tar -zxf [openssl_archive].tar.gz && cd [openssl_archive];`
`./config && make && make test && make install`

Verify your openssl install with:
`openssl version`

## Make sure you have CMake 3.15+
### On Mac:
`brew install cmake`

### On Debian distros (tried on Ubuntu 18.04 and debian10)
On debian distros the maximum version that apt getable is 3.10.x, which is not good. 
Go to `https://cmake.org/download/` and download a minimum of version 3.15.x in a tar.gz format

Then run the following to install the package:
`tar -zxf [cmake_archive].tar.gz && cd [cmake_archive];`
`./bootstrap && make && make install`

Verify your cmake install with:
`cmake --version`

## Integrate and release to your local peacemakr-go-sdk clone - Golang:
`./bin/release-golang.sh /path/to/peacemakr-go-sdk release`

For a debug build

`./bin/release-golang.sh /path/to/peacemakr-go-sdk`

## Build - For iOS
`cd /path/to/peacemakr-core-crypto/bin && ./release-ios.sh /where/to/put/build/artifacts [is_first_build]`


## Build - For Android (doesn't work yet)
`cd /path/to/peacemakr-core-crypto/bin && ANDROID_NDK_ROOT=/path/to/android/ndk-bundle ./release-android.sh /where/to/put/build/artifacts [is_first_build]`

Make sure you have the [Android NDK installed](https://developer.android.com/ndk/guides): 

## Build - Java
`./bin/release_java.sh /path/to/java/sdk release`

## Build - Python
Docker:
`cd /path/to/peacemakr-core-crypto/bin && ./release-python.sh release`

Local (install into virtualenv):
`cd /path/to/peacemakr-core-crypto/bin && ./release-python.sh local /path/to/virtualenv/lib/site-packages release`

Local (install into machine python):
`cd /path/to/peacemakr-core-crypto/bin && ./release-python.sh local none release`

## Potential errors in tests when compiling:
If you get an error informing you that the system does not find the pthread lib (during the testing phase), go to `src/ffi/cpp/tests/CmakeList.txt` and change the line containing `set(CMAKE_CXX_STANDARD 11)` to `set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pthread")`.
