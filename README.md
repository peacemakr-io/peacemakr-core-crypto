# peacemakr-core-crypto
[![CircleCI](https://circleci.com/gh/notasecret/peacemakr-core-crypto/tree/master.svg?style=svg&circle-token=a5e0dd516384638b6e97cd79c7963d8081873df2)](https://circleci.com/gh/notasecret/peacemakr-core-crypto/tree/master)

## About
This package defines the core crypto functionality for peacemakr.

## Documentation
From the repository base directory,
`./bin/serve-docs.sh` will set up a docker image that serves the doxygen docs on `localhost:3000`

## Make sure you have OpenSSL 1.1 or greater installed:

`brew install openssl@1.1`

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
`cd /path/to/peacemakr-core-crypto/bin && ./release-python release`
Local (install into virtualenv):
`cd /path/to/peacemakr-core-crypto/bin && ./release-python local /path/to/virtualenv/lib/site-packages release`
Local (install into machine python):
`cd /path/to/peacemakr-core-crypto/bin && ./release-python local none release`
