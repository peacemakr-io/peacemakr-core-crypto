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

set(CMAKE_C_FLAGS "-Os -fPIC -fstack-protector-strong -Wall")

set(ALL_C_SOURCE_FILES "")

if (ANDROID_ABI)
    set(OPENSSL_ROOT_DIR ${OPENSSL_ROOT_DIR}/${ANDROID_ABI} CACHE PATH "" FORCE)
    set(OPENSSL_INCLUDE_DIR ${OPENSSL_ROOT_DIR}/include)
    include_directories(${OPENSSL_INCLUDE_DIR})

    set(OPENSSL_SSL_LIBRARY ${OPENSSL_ROOT_DIR}/lib/libssl.a)
    add_library(OpenSSL::SSL SHARED IMPORTED)
    set_target_properties(OpenSSL::SSL PROPERTIES IMPORTED_LOCATION ${OPENSSL_SSL_LIBRARY})

    set(OPENSSL_CRYPTO_LIBRARY ${OPENSSL_ROOT_DIR}/lib/libcrypto.a)
    add_library(OpenSSL::Crypto SHARED IMPORTED)
    set_target_properties(OpenSSL::Crypto PROPERTIES IMPORTED_LOCATION ${OPENSSL_CRYPTO_LIBRARY})
else (ANDROID_ABI)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
    find_package(OpenSSL 1.1 REQUIRED)
endif (ANDROID_ABI)

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
    doxygen_add_docs(doxygen
            ${CMAKE_CURRENT_SOURCE_DIR}/README.md
            ${CMAKE_CURRENT_SOURCE_DIR}/src/core/include/peacemakr
            COMMENT "Generate documentation pages")
endif (DOXYGEN_FOUND)

# INSTALL

export(TARGETS peacemakr-core-crypto FILE ${CMAKE_BINARY_DIR}/peacemakr_core_crypto_targets.cmake)
export(PACKAGE peacemakr-core-crypto)
export(PACKAGE peacemakr-core-crypto-cpp)

# Create the FooBarConfig.cmake and FooBarConfigVersion files
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

