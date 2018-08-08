#
# Created by Aman LaChapelle on 7/20/18.
#
# peacemakr-core-crypto
# Copyright (c) 2018 peacemakr
# Full license at peacemakr-core-crypto/LICENSE.txt
#

cmake_minimum_required(VERSION 3.10)
project(peacemakr_core_crypto C)

file(GLOB INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include/*.h)
file(GLOB SOURCES_C ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)
file(GLOB SOURCES_H ${CMAKE_CURRENT_SOURCE_DIR}/src/*.h)

set(ALL_C_SOURCE_FILES ${SOURCES_C} ${SOURCES_H} ${INCLUDES} ${ALL_C_SOURCE_FILES} PARENT_SCOPE)

add_library(peacemakr-core-crypto SHARED ${SOURCES_C} ${SOURCES_H} ${INCLUDES})
add_definitions(-DOPENSSL_MIN_API=0x10100000L)
target_include_directories(peacemakr-core-crypto
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(peacemakr-core-crypto
        PUBLIC OpenSSL::SSL OpenSSL::Crypto)
