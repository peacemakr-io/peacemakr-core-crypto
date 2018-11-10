# peacemakr-core-crypto

## About

This package defines the core crypto functionality for peacemakr.

## Documentation
From the repository base directory,
`./bin/serve-docs.sh` will set up a docker image that serves the doxygen docs on `localhost:3000`

---

## Build - Golang
`docker build -t corecrypto . -f docker/go.Dockerfile`

NOTE: we need to tag the image (will automate this): `docker tag  corecrypto:latest peacemakr-core-crypto:go-base-0.0.6`

## Build - Swift
`cd /path/to/peacemakr-core-crypto/bin && ./release-ios.sh /where/to/put/build/artifacts`