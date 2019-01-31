# peacemakr-core-crypto
[![CircleCI](https://circleci.com/gh/notasecret/peacemakr-core-crypto/tree/master.svg?style=svg)](https://circleci.com/gh/notasecret/peacemakr-core-crypto/tree/master)

## About
This package defines the core crypto functionality for peacemakr.

## Documentation
From the repository base directory,
`./bin/serve-docs.sh` will set up a docker image that serves the doxygen docs on `localhost:3000`

## Build Dependencies - Golang
`docker build -t corecrypto-dependencies:latest . -f docker/go-dependencies.Dockerfile --build-arg="CMAKE_BUILD_TYPE=RELEASE"`

## Build - Golang
`docker build -t corecrypto:latest . -f docker/go.Dockerfile`
## Build (release) - Golang
`docker build -t corecrypto:latest . -f docker/go.Dockerfile --build-arg="CMAKE_BUILD_TYPE=RELEASE"`

## Integrate and release - Golang:
`./bin/release-golang.sh /path/to/peacemakr-api release`
For a debug build
`./bin/release-golang.sh /path/to/peacemakr-api`

## Build - Swift
`cd /path/to/peacemakr-core-crypto/bin && ./release-ios.sh /where/to/put/build/artifacts`
