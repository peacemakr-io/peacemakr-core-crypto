FROM debian:latest

# libssl-dev has libssl and libcrypto
RUN apt-get update -y && apt-get install -y wget gnupg software-properties-common libssl-dev make git

RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -

RUN add-apt-repository "deb http://apt.llvm.org/stretch/ llvm-toolchain-stretch-6.0 main"

RUN apt-get update -y && apt-get install -y \
clang-6.0 clang-tools-6.0 llvm-6.0 libfuzzer-6.0-dev lld-6.0 clang-format-6.0

ENV PATH=/usr/lib/llvm-6.0/bin:$PATH

RUN update-alternatives --install /usr/bin/cc cc /usr/lib/llvm-6.0/bin/clang 100

ADD "https://cmake.org/files/v3.12/cmake-3.12.0-Linux-x86_64.sh" "/cmake-3.12.0-Linux-x86_64.sh"
RUN mkdir /opt/cmake &&\
        sh /cmake-3.12.0-Linux-x86_64.sh --prefix=/opt/cmake --skip-license &&\
        ln -s /opt/cmake/bin/cmake /usr/local/bin/cmake

WORKDIR /opt

ADD CMakeLists.txt /opt/CMakeLists.txt
ADD src /opt/src
ADD cmake /opt/cmake

RUN mkdir -p build && cd build && cmake .. && make

CMD ["bash"]