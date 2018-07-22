#
# Created by Aman LaChapelle on 7/20/18.
#
# peacemakr-core-crypto
# Copyright (c) 2018 peacemakr
# Full license at peacemakr-core-crypto/LICENSE.txt
#

cmake_minimum_required(VERSION 3.10)
project(peacemakr_core_crypto)

file(GLOB INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include/*.h)
file(GLOB SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)

set(ALL_CXX_SOURCE_FILES ${SOURCES} ${INCLUDES} ${ALL_C_SOURCE_FILES} PARENT_SCOPE)

add_library(peacemakr-core-crypto SHARED ${SOURCES} ${INCLUDES})
target_include_directories(peacemakr-core-crypto
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(peacemakr-core-crypto
        PUBLIC OpenSSL::SSL OpenSSL::Crypto
)