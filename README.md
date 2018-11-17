# peacemakr-core-crypto

## About

This package defines the core crypto functionality for peacemakr.

## Documentation
From the repository base directory,
`./bin/serve-docs.sh` will set up a docker image that serves the doxygen docs on `localhost:3000`

---

## Build - Golang
`docker build -t corecrypto:latest . -f docker/go.Dockerfile`

## Integrate - Golang:
`docker run corecrypto:latest cat /go/src/peacemakr/crypto/crypto.go > src/ffi/go/src/peacemakr/crypto/crypto.go`
`docker run corecrypto:latest cat /go/src/peacemakr/crypto/crypto_test.go > src/ffi/go/src/peacemakr/crypto/crypto_test.go`

`docker run corecrypto:latest cat /usr/local/include/peacemakr/crypto.h > src/core/include/peacemakr/crypto.h`
`docker run corecrypto:latest cat /usr/local/include/peacemakr/random.h > src/core/include/peacemakr/random.h`

Copy glue to peacemakr:
`cp src/ffi/go/src/peacemakr/crypto/crypto* ~/peacemakr/peacemakr-api/src/peacemakr/crypto/.`
`cp src/core/include/peacemakr/* ~/peacemakr/peacemakr-api/include/peacemakr/.`

## Build - Swift
`cd /path/to/peacemakr-core-crypto/bin && ./release-ios.sh /where/to/put/build/artifacts`
