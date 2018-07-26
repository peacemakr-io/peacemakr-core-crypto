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
file(GLOB SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)

add_custom_target(get-modes
        COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/get-modes.sh ${CMAKE_CURRENT_SOURCE_DIR}
)

set(ALL_C_SOURCE_FILES ${SOURCES} ${INCLUDES} ${ALL_C_SOURCE_FILES} PARENT_SCOPE)

add_library(peacemakr-core-crypto SHARED ${SOURCES} ${INCLUDES})
add_definitions(-DOPENSSL_MIN_API=0x10100000L)
add_dependencies(peacemakr-core-crypto get-modes)
target_include_directories(peacemakr-core-crypto
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(peacemakr-core-crypto
        PUBLIC OpenSSL::SSL OpenSSL::Crypto)
