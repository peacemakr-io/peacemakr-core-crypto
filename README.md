# Peacemakr CoreCrypto Library
![](https://github.com/peacemakr-io/peacemakr-core-crypto/workflows/Build%20and%20Test/badge.svg) ![](https://github.com/peacemakr-io/peacemakr-core-crypto/workflows/Upload%20Release%20Asset/badge.svg)

## About
This package defines the core crypto functionality for peacemakr.

# Download and Install Binaries
```bash
wget https://github.com/peacemakr-io/peacemakr-core-crypto/releases/download/latest/libpeacemakr-core-crypto-<os>-<arch>.tar.gz -O /usr/local
echo 'export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib' >> ~/.bashrc
```

# Build and Install Library from Source
Assuming you have [OpenSSL 1.1+](#openssl-11) and [CMake 3.15+](#cmake-315) 
```bash
git clone https://github.com/peacemakr-io/peacemakr-core-crypto.git
cd peacemakr-core-crypto
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make check install
# To helps runtime dependencies find the library
echo 'export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib' >> ~/.bashrc
```

# Development Setup
### OpenSSL 1.1+:
#### On Mac:
`brew install openssl@1.1`

#### On Debian distros (tried on Ubuntu 18.04 and debian10):
On debian distros the maximum version of OpenSSL that apt-get-able is 1.0.x, so you need to manually install. 
Go to `https://www.openssl.org/source/` and download the tar.gz corresponding to the 1.1-stable

Then run the following to install the package:
```bash
git clone -b OpenSSL_1_1_1-stable --single-branch https://github.com/openssl/openssl.git
cd openssl
./config && make && make test && make install
```

Verify your openssl install with:
`openssl version`

### CMake 3.15+:
#### On Mac:
`brew install cmake`

#### On Debian distros (tried on Ubuntu 18.04 and debian10):
On debian distros the maximum version that apt getable is 3.10.x. 
Go to `https://cmake.org/download/` and download a minimum of version 3.15.x in a tar.gz format

Then run the following to install the package:
```bash
tar -zxf [cmake_archive].tar.gz && cd [cmake_archive]
./bootstrap && make && make install
```

Verify your cmake install with:
`cmake --version`

## Documentation
From the repository base directory,
`./bin/serve-docs.sh` will set up a docker image that serves the doxygen docs on `localhost:3000`

## Release - Golang:
`./bin/release-golang.sh /path/to/peacemakr-go-sdk release1

For a debug build

`./bin/release-golang.sh /path/to/peacemakr-go-sdk`

## Release - Java
`./bin/release_java.sh /path/to/java/sdk release`

For a debug build

`./bin/release_java.sh /path/to/java/sdk`

## Release - Python
Docker:
`cd /path/to/peacemakr-core-crypto/bin && ./release-python.sh release`

Local (install into virtualenv):
`cd /path/to/peacemakr-core-crypto/bin && ./release-python.sh local /path/to/virtualenv/lib/site-packages release`

Local (install into machine python):
`cd /path/to/peacemakr-core-crypto/bin && ./release-python.sh local none release`

## Under development
### Build - iOS
`cd /path/to/peacemakr-core-crypto/bin && ./release-ios.sh /where/to/put/build/artifacts [is_first_build]`


### Build - Android
Make sure you have the [Android NDK installed](https://developer.android.com/ndk/guides)

`cd /path/to/peacemakr-core-crypto/bin && ANDROID_NDK_ROOT=/path/to/android/ndk-bundle ./release-android.sh /where/to/put/build/artifacts [is_first_build]`
