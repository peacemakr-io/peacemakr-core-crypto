# peacemakr-core-crypto
[![CircleCI](https://circleci.com/gh/notasecret/peacemakr-core-crypto/tree/master.svg?style=svg&circle-token=a5e0dd516384638b6e97cd79c7963d8081873df2)](https://circleci.com/gh/notasecret/peacemakr-core-crypto/tree/master)

## About
This package defines the core crypto functionality for peacemakr.

## Documentation
From the repository base directory,
`./bin/serve-docs.sh` will set up a docker image that serves the doxygen docs on `localhost:3000`

## Make sure you have OpenSSL 1.1 or greater installed:

`brew install openssl@1.1`

## Build Dependencies - Golang
`docker build -t corecrypto-dependencies:latest . -f docker/go-dependencies.Dockerfile --build-arg="CMAKE_BUILD_TYPE=RELEASE"`
`docker tag corecrypto-dependencies:latest 716293438869.dkr.ecr.us-east-2.amazonaws.com/corecrypto-dependencies:latest`

Make sure to build with the `RELEASE` flag in docker as the address sanitizer enabled in debug mode does not play
well with Alpine linux and works best when testing on the host. 

## Build - Golang
`docker build -t corecrypto:latest . -f docker/go.Dockerfile --build-arg="CMAKE_BUILD_TYPE=RELEASE"`

`docker tag corecrypto:latest 716293438869.dkr.ecr.us-east-2.amazonaws.com/corecrypto:latest`

## Integrate and release to your local peacemakr-api clone - Golang:
`./bin/release-golang.sh /path/to/peacemakr-api release`

For a debug build

`./bin/release-golang.sh /path/to/peacemakr-api`

## Build - For iOS
`cd /path/to/peacemakr-core-crypto/bin && ./release-ios.sh /where/to/put/build/artifacts [is_first_build]`


## Build - For Android (doesn't work yet)
`cd /path/to/peacemakr-core-crypto/bin && ANDROID_NDK_ROOT=/path/to/android/ndk-bundle ./release-android.sh /where/to/put/build/artifacts [is_first_build]`

Make sure you have the [Android NDK installed](https://developer.android.com/ndk/guides): 

## Build - Java
`./bin/release_java.sh -release 1.0.0`
