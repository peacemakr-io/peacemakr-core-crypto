#
# Created by Aman LaChapelle on 7/20/18.
#
# peacemakr-core-crypto
# Copyright (c) 2018 peacemakr
# Full license at peacemakr-core-crypto/LICENSE.txt
#

IF(CMAKE_BUILD_TYPE MATCHES RELEASE)
    message("Disabling all logging")
    add_definitions(-DPEACEMAKR_LOG_LEVEL=5)
ENDIF(CMAKE_BUILD_TYPE MATCHES RELEASE)

include(CheckFunctionExists)
check_function_exists(memset_s HAS_MEMSET_S)
if (NOT HAS_MEMSET_S)
    message(WARNING "memset_s function does not exist in this compiler, zeroing secure memory may be optimized away")
    add_definitions(-DPEACEMAKR_NO_MEMSET_S)
endif (NOT HAS_MEMSET_S)

file(GLOB INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include/peacemakr/*.h)
file(GLOB SOURCES_C ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)
file(GLOB SOURCES_H ${CMAKE_CURRENT_SOURCE_DIR}/src/*.h)

set(ALL_C_SOURCE_FILES ${SOURCES_C} ${SOURCES_H} ${INCLUDES} ${ALL_C_SOURCE_FILES} PARENT_SCOPE)

add_library(peacemakr-core-crypto SHARED ${SOURCES_C} ${SOURCES_H} ${INCLUDES})
add_definitions(-DOPENSSL_MIN_API=0x10100000L)
target_include_directories(peacemakr-core-crypto
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/peacemakr
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(peacemakr-core-crypto
        PUBLIC OpenSSL::SSL OpenSSL::Crypto)
set_target_properties(peacemakr-core-crypto PROPERTIES
        PUBLIC_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/include/peacemakr/crypto.h;${CMAKE_CURRENT_SOURCE_DIR}/include/peacemakr/random.h"
)

install(TARGETS peacemakr-core-crypto
        EXPORT peacemakr-core-crypto-targets
        LIBRARY DESTINATION lib
        PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_PREFIX}/include/peacemakr"
        COMPONENT dev
)
