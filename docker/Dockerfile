FROM debian:latest

# libssl-dev has libssl and libcrypto
RUN apt-get update -y && apt-get install -y wget gnupg software-properties-common libssl-dev cmake make

RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -

RUN add-apt-repository "deb http://apt.llvm.org/stretch/ llvm-toolchain-stretch-6.0 main"

RUN apt-get update -y && apt-get install -y \
clang-6.0 clang-tools-6.0 llvm-6.0 libfuzzer-6.0-dev lld-6.0 clang-format-6.0

ENV PATH=/usr/lib/llvm-6.0/bin:$PATH

RUN update-alternatives --install /usr/bin/cc cc /usr/lib/llvm-6.0/bin/clang 100

WORKDIR /opt

ADD CMakeLists.txt /opt/CMakeLists.txt
ADD src /opt/src

#RUN mkdir -p build && cd build && cmake .. && make

CMD ["bash"]