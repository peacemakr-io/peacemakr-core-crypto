#
# Created by Aman LaChapelle on 7/20/18.
#
# peacemakr-core-crypto
# Copyright (c) 2018 peacemakr
# Full license at peacemakr-core-crypto/LICENSE.txt
#

FROM corecrypto-dependencies:latest as builder

FROM alpine:3.8

RUN apk add --no-cache libbsd

COPY --from=builder /usr/local/lib/cmake /usr/local/lib/cmake
COPY --from=builder /usr/local/lib/libpeacemakr* /usr/local/lib/
COPY --from=builder /usr/local/include/peacemakr /usr/local/include/peacemakr
COPY --from=builder /usr/include/openssl /usr/include/openssl
COPY --from=builder /opt/src/ffi/go/src /go/src

ENV GOPATH=/go
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

WORKDIR /go/src
