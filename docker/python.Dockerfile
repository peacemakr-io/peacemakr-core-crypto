FROM python:alpine

RUN apk add --no-cache git alpine-sdk perl cmake linux-headers

WORKDIR /opt
RUN git clone -b OpenSSL_1_1_1-stable --single-branch https://github.com/openssl/openssl.git

RUN cd openssl \
    && ./config --prefix=/usr --openssldir=/etc/ssl --libdir=lib no-async \
    && make test MANSUFFIX=ssl install

WORKDIR /opt

ADD CMakeLists.txt /opt/CMakeLists.txt
ADD src/core /opt/src/core
# Python bindings and test
ADD src/ffi/python /opt/src/ffi/python
# C++ bindings and tests
ADD src/ffi/cpp /opt/src/ffi/cpp
# Build requirements
ADD src/ffi/CMakeLists.txt /opt/src/ffi/CMakeLists.txt
ADD cmake /opt/cmake

WORKDIR /opt

ARG CMAKE_BUILD_TYPE=DEBUG
RUN mkdir -p build && cd build \
&& cmake .. \
-DPEACEMAKR_BUILD_PYTHON=ON \
-DASAN=OFF \
-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} \
&& make check install
