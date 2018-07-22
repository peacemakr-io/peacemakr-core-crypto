#
# Created by Aman LaChapelle on 7/20/18.
#
# peacemakr-core-crypto
# Copyright (c) 2018 peacemakr
# Full license at peacemakr-core-crypto/LICENSE.txt
#

cmake_minimum_required(VERSION 3.10)
project(peacemakr_core_crypto)

set(CMAKE_CXX_STANDARD 11)

set(CMAKE_CXX_FLAGS "-Os")

find_package(OpenSSL REQUIRED)

set(ALL_CXX_SOURCE_FILES "")

add_subdirectory(src/core)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/AddClangFormat.cmake)