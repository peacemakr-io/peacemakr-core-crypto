cmake_minimum_required(VERSION 3.5)
project(peacemakr_sdk)

set(CMAKE_CXX_STANDARD 11)

find_package(OpenSSL REQUIRED)

add_subdirectory(src/core)