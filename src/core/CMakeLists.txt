#
# Created by Aman LaChapelle on 7/20/18.
#
# peacemakr-core-crypto
# Copyright (c) 2018 peacemakr
# Full license at peacemakr-core-crypto/LICENSE.txt
#

cmake_minimum_required(VERSION 3.10)
project(peacemakr_core_crypto)

file(GLOB INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp)
file(GLOB SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)

set(ALL_CXX_SOURCE_FILES ${SOURCES} ${INCLUDES} ${ALL_CXX_SOURCE_FILES} PARENT_SCOPE)

add_library(peacemakr-core-crypto STATIC ${SOURCES} ${INCLUDES})
target_include_directories(peacemakr-core-crypto
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(peacemakr-core-crypto
        PUBLIC OpenSSL::SSL OpenSSL::Crypto
        PRIVATE glog::glog
)