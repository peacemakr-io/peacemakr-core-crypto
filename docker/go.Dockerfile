#
# Created by Aman LaChapelle on 7/20/18.
#
# peacemakr-core-crypto
# Copyright (c) 2018 peacemakr
# Full license at peacemakr-core-crypto/LICENSE.txt
#

FROM corecrypto-dependencies:latest as builder

FROM alpine:3.10

RUN apk add --no-cache

COPY --from=builder /go/src /go/src

ENV GOPATH=/go

WORKDIR /go/src
