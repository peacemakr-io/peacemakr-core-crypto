# Peacemakr CoreCrypto Library
![](https://github.com/peacemakr-io/peacemakr-core-crypto/workflows/Build%20and%20Test/badge.svg) ![](https://github.com/peacemakr-io/peacemakr-core-crypto/workflows/Upload%20Release%20Asset/badge.svg)

## About
Peacemakr's Core Cryptography SDK. Defines crypto functionality for all Peacemakr SDKs

We take security and trust very seriously. If you believe you have found a security issue, please responsibly disclose by [contacting us](mailto:security@peacemakr.io).

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
# JAVA_HOME needs to be set prior to running cmake(). Use Java8 for compilation, JavaSDK is compiled using Java8 
export JAVA_HOME=/Library/Java/JavaVirtualMachines/<JAVA_RELEASE_VERSION>/Contents/Home
cmake .. -DCMAKE_BUILD_TYPE=Release
make check-peacemakr-core-crypto install
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
`./bin/release-java.sh /path/to/java/sdk release`

For a debug build

`./bin/release-java.sh /path/to/java/sdk`

Prepare release of core-crypto-crypto jar to maven:
`cd ../peacemakr-core-crypto/src/ffi/java`

- View a list of tasks:
`./gradlew tasks`

- Build peacemakr-core-crypto jar:
`./gradlew build`

- Build and release core-crypto-crypto jar to local maven (~/.m2/repository/io/peacemakr/peacemakr-core-crypto):
`./gradlew publishMavenJavaPublicationToMavenLocal -Prelease`

- Build and push core-crypto-crypto jar to OSSRH:
`./gradlew publishMavenJavaPublicationToMavenRepository -Prelease`

## Release - Python
Docker:
`cd /path/to/peacemakr-core-crypto/bin && ./release-python.sh release`

Local (install into virtualenv):
`cd /path/to/peacemakr-core-crypto/bin && ./release-python.sh local /path/to/virtualenv/lib/site-packages release`

Local (install into machine python):
`cd /path/to/peacemakr-core-crypto/bin && ./release-python.sh local none release`

## macOS 10.15
Due to the new security requirements for macOS Catalina, you may run into an issue where `dlopen` fails because macOS
could not identify the developer.

There are several solutions (temporary):

### Manually sign 
```bash
xattr -cr /path/to/peacemakr_core_crypto.dylib
codesign --force --deep --sign - /path/to/peacemakr_core_crypto.dylib
``` 

### Developer tools override
Install Xcode and in System Preferences navigate to `Security & Privacy -> Privacy -> Developer Tools` and allow 
Terminal to run software locally. If you do not have Xcode installed, you will not see the `Developer Tools` entry 
in the list on the left hand side.

## Under development
### Build - iOS
`cd /path/to/peacemakr-core-crypto/bin && ./release-ios.sh /where/to/put/build/artifacts [is_first_build]`


### Build - Android
Make sure you have the [Android NDK installed](https://developer.android.com/ndk/guides)

`cd /path/to/peacemakr-core-crypto/bin && ANDROID_NDK_ROOT=/path/to/android/ndk-bundle ./release-android.sh /where/to/put/build/artifacts [is_first_build]`
