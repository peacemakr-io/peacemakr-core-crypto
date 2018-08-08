#
# Created by Aman LaChapelle on 7/20/18.
#
# peacemakr-core-crypto
# Copyright (c) 2018 peacemakr
# Full license at peacemakr-core-crypto/LICENSE.txt
#

cmake_minimum_required(VERSION 3.10)
project(peacemakr_core_crypto C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_C_FLAGS "-Os -std=c11 -fstack-protector-strong")

find_package(OpenSSL REQUIRED)

set(ALL_C_SOURCE_FILES "")

add_subdirectory(src/core)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/AddClangFormat.cmake)