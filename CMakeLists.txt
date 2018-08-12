#
# Created by Aman LaChapelle on 7/20/18.
#
# peacemakr-core-crypto
# Copyright (c) 2018 peacemakr
# Full license at peacemakr-core-crypto/LICENSE.txt
#

cmake_minimum_required(VERSION 3.10)
project(peacemakr_core_crypto C)

set(PEACEMAKR_CORE_CRYPTO_MAJOR_VERSION 0)
set(PEACEMAKR_CORE_CRYPTO_MINOR_VERSION 1)
set(PEACEMAKR_CORE_CRYPTO_PATCH_VERSION 0)
set(PEACEMAKR_CORE_CRYPTO_VERSION
        ${PEACEMAKR_CORE_CRYPTO_MAJOR_VERSION}.${PEACEMAKR_CORE_CRYPTO_MINOR_VERSION}.${PEACEMAKR_CORE_CRYPTO_PATCH_VERSION})

option(BUILD_TESTS "Whether or not to build the tests" ON)


set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_C_FLAGS "-Os -fstack-protector-strong -Wall")

find_package(OpenSSL 1.1 REQUIRED)

set(ALL_C_SOURCE_FILES "")

add_subdirectory(src/core)
if (BUILD_TESTS)
    add_subdirectory(src/test)
endif(BUILD_TESTS)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/AddClangFormat.cmake)

# INSTALL

export(TARGETS peacemakr-core-crypto FILE ${CMAKE_BINARY_DIR}/peacemakr_core_crypto_targets.cmake)
export(PACKAGE peacemakr-core-crypto)

# Create the FooBarConfig.cmake and FooBarConfigVersion files
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/peacemakr-core-crypto-config.cmake.in
        "${CMAKE_BINARY_DIR}/peacemakr-core-crypto-config.cmake" @ONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/peacemakr-core-crypto-config.cmake.in
        "${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/peacemakr-core-crypto-config.cmake" @ONLY)
# ... for both
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/peacemakr-core-crypto-config-version.cmake.in
        "${CMAKE_BINARY_DIR}/peacemakr-core-crypto-config-version.cmake" @ONLY)

# Install the FooBarConfig.cmake and FooBarConfigVersion.cmake
install(FILES
        "${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/peacemakr-core-crypto-config.cmake"
        "${CMAKE_BINARY_DIR}/peacemakr-core-crypto-config-version.cmake"
        DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake" COMPONENT dev)

# Install the export set for use with the install-tree
install(EXPORT peacemakr-core-crypto-targets
        DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake" COMPONENT dev)

