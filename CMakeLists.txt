#
# Created by Aman LaChapelle on 7/20/18.
#
# peacemakr-core-crypto
# Copyright (c) 2018 peacemakr
# Full license at peacemakr-core-crypto/LICENSE.txt
#

cmake_minimum_required(VERSION 3.10)
project(peacemakr_core_crypto C CXX)

set(PEACEMAKR_CORE_CRYPTO_MAJOR_VERSION 0)
set(PEACEMAKR_CORE_CRYPTO_MINOR_VERSION 1)
set(PEACEMAKR_CORE_CRYPTO_PATCH_VERSION 0)
set(PEACEMAKR_CORE_CRYPTO_VERSION
        ${PEACEMAKR_CORE_CRYPTO_MAJOR_VERSION}.${PEACEMAKR_CORE_CRYPTO_MINOR_VERSION}.${PEACEMAKR_CORE_CRYPTO_PATCH_VERSION})

option(BUILD_TESTS "Whether or not to build the tests" ON)
option(STATIC_LIBC "Build against static libc")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(PEACEMAKR_BUILD_WEB "Whether to build the WASM bindings" OFF)

if (${PEACEMAKR_BUILD_WEB})
    set(CMAKE_C_FLAGS_DEBUG "-O0 -g")
else()
    set(CMAKE_C_FLAGS_DEBUG "-O0 -g -fstack-protector-strong")
endif()
set(CMAKE_C_FLAGS_RELEASE "-Os -fPIC -Wall -fvisibility=hidden -ffunction-sections")

set(ALL_C_SOURCE_FILES "")

set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL 1.1 REQUIRED)

add_subdirectory(src/core)
add_subdirectory(src/ffi)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/AddClangFormat.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/AddClangAnalyzer.cmake)

# DOCS
find_package(Doxygen)
if (DOXYGEN_FOUND)
    set(DOXYGEN_EXTRACT_STATIC YES)
    # Workaround for what I assume is a bug in cmake 3.12
    set(DOXYGEN_LATEX_MAKEINDEX_CMD "makeindex")
    set(DOXYGEN_GENERATE_HTML YES)
    set(DOXYGEN_OPTIMIZE_OUTPUT_FOR_C YES)
    set(DOXYGEN_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/docs)
    set(DOXYGEN_USE_MDFILE_AS_MAINPAGE ${CMAKE_CURRENT_SOURCE_DIR}/README.md)
    if((CMAKE_BUILD_TYPE MATCHES RELEASE) OR (CMAKE_BUILD_TYPE MATCHES Release))
        doxygen_add_docs(doxygen
                ${CMAKE_CURRENT_SOURCE_DIR}/README.md
                ${CMAKE_CURRENT_SOURCE_DIR}/src/core/include/peacemakr
                COMMENT "Generate documentation pages")
    else()
        set(DOXYGEN_EXTRACT_ALL YES)
        doxygen_add_docs(doxygen
                ${CMAKE_CURRENT_SOURCE_DIR}/README.md
                ${CMAKE_CURRENT_SOURCE_DIR}/src/core
                COMMENT "Generate documentation pages")
    endif()
endif (DOXYGEN_FOUND)

# INSTALL

export(TARGETS peacemakr-core-crypto FILE ${CMAKE_BINARY_DIR}/peacemakr_core_crypto_targets.cmake)
export(PACKAGE peacemakr-core-crypto)
export(PACKAGE peacemakr-core-crypto-cpp)

# Create the peacemakr-core-crypto-config.cmake and peacemakr-core-crypto-config-version files
set(CONF_INCLUDE_DIRS "${CMAKE_INSTALL_PREFIX}/include")
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/peacemakr-core-crypto-config.cmake.in
        "${CMAKE_BINARY_DIR}/peacemakr-core-crypto-config.cmake" @ONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/peacemakr-core-crypto-config.cmake.in
        "${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/peacemakr-core-crypto-config.cmake" @ONLY)
# ... for both
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/peacemakr-core-crypto-config-version.cmake.in
        "${CMAKE_BINARY_DIR}/peacemakr-core-crypto-config-version.cmake" @ONLY)

# Install the *-config.cmake and *-config-version.cmake
install(FILES
        "${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/peacemakr-core-crypto-config.cmake"
        "${CMAKE_BINARY_DIR}/peacemakr-core-crypto-config-version.cmake"
        DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake" COMPONENT dev)

# Install the export set for use with the install-tree
install(EXPORT peacemakr-core-crypto-targets
        DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake" COMPONENT dev)

