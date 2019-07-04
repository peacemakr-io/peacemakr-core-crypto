FROM alpine:3.8 as builder

RUN apk add --no-cache git alpine-sdk perl cmake linux-headers doxygen

WORKDIR /opt
RUN git clone -b OpenSSL_1_1_1-stable --single-branch https://github.com/openssl/openssl.git

RUN cd openssl \
    && ./config --prefix=/usr --openssldir=/etc/ssl --libdir=lib no-async \
    && make test MANSUFFIX=ssl install

WORKDIR /opt

ADD CMakeLists.txt /opt/CMakeLists.txt
ADD src /opt/src
ADD cmake /opt/cmake
ADD README.md README.md

RUN mkdir -p build && cd build && cmake .. && make doxygen

FROM golang:alpine3.8

COPY --from=builder /opt/docs /opt/docs

ENV DOC_DIR=/opt/docs
ADD docker/resources/docserver.go /opt/docserver.go

CMD go run /opt/docserver.go
