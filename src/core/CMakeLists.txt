#
# Created by Aman LaChapelle on 7/20/18.
#
# peacemakr-core-crypto
# Copyright (c) 2018 peacemakr
# Full license at peacemakr-core-crypto/LICENSE.txt
#

if((CMAKE_BUILD_TYPE MATCHES RELEASE) OR (CMAKE_BUILD_TYPE MATCHES Release))
    message("Setting log to release")
    add_definitions(-DPEACEMAKR_LOG_LEVEL=1)
endif()

include(CheckFunctionExists)
check_function_exists(memset_s HAS_MEMSET_S)
if (NOT HAS_MEMSET_S)
    message(WARNING "memset_s function does not exist in this compiler, zeroing secure memory may be optimized away")
    add_definitions(-DPEACEMAKR_NO_MEMSET_S)
endif (NOT HAS_MEMSET_S)

file(GLOB INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include/peacemakr/*.h)
file(GLOB SOURCES_C ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)
file(GLOB SOURCES_H ${CMAKE_CURRENT_SOURCE_DIR}/src/*.h)

add_library(peacemakr-core-crypto SHARED ${SOURCES_C} ${SOURCES_H} ${INCLUDES})
add_definitions(-DOPENSSL_MIN_API=0x10100000L)
target_include_directories(peacemakr-core-crypto
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/peacemakr>
               $<INSTALL_INTERFACE:include>
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)
if (APPLE)
    target_link_libraries(peacemakr-core-crypto
            PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    target_link_options(peacemakr-core-crypto PRIVATE -Wl,-dead_strip)
else()
    target_link_libraries(peacemakr-core-crypto
            PRIVATE OpenSSL::SSL OpenSSL::Crypto bsd -ldl)
    target_link_options(peacemakr-core-crypto PRIVATE -Wl,--gc-sections)
endif()
set_target_properties(peacemakr-core-crypto PROPERTIES
        PUBLIC_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/include/peacemakr/crypto.h;${CMAKE_CURRENT_SOURCE_DIR}/include/peacemakr/random.h"
)

if ((CMAKE_BUILD_TYPE MATCHES RELEASE) OR (CMAKE_BUILD_TYPE MATCHES Release))
    if (APPLE)
        add_custom_command(TARGET peacemakr-core-crypto POST_BUILD
                COMMAND ${CMAKE_STRIP} -x $<TARGET_FILE:peacemakr-core-crypto>)
    else()
        add_custom_command(TARGET peacemakr-core-crypto POST_BUILD
                COMMAND ${CMAKE_STRIP} $<TARGET_FILE:peacemakr-core-crypto>)
    endif()
endif ()

install(TARGETS peacemakr-core-crypto
        EXPORT peacemakr-core-crypto-targets
        LIBRARY DESTINATION lib
        PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_PREFIX}/include/peacemakr"
        COMPONENT dev
)

if (BUILD_TESTS)
    add_subdirectory(test)
endif(BUILD_TESTS)

set(ALL_C_SOURCE_FILES ${SOURCES_C} ${SOURCES_H} ${INCLUDES} ${ALL_C_SOURCE_FILES} PARENT_SCOPE)
