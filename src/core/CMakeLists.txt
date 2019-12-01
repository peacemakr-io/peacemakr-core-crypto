#
# Created by Aman LaChapelle on 7/20/18.
#
# peacemakr-core-crypto
# Copyright (c) 2018 peacemakr
# Full license at peacemakr-core-crypto/LICENSE.txt
#

include(CheckFunctionExists)
include(CheckCCompilerFlag)

if((CMAKE_BUILD_TYPE MATCHES RELEASE) OR (CMAKE_BUILD_TYPE MATCHES Release))
    message(STATUS "Setting log to release")
    add_definitions(-DPEACEMAKR_LOG_LEVEL=1)
endif()

check_function_exists(memset_s HAS_MEMSET_S)
if (NOT HAS_MEMSET_S)
    message(WARNING "memset_s function does not exist in this compiler, zeroing secure memory may be optimized away")
    add_definitions(-DPEACEMAKR_NO_MEMSET_S)
endif (NOT HAS_MEMSET_S)

check_function_exists(arc4random_buf HAS_BSD)
if (NOT HAS_BSD)
    add_definitions(-DPEACEMAKR_NEEDS_BSD)
endif()

file(GLOB INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include/peacemakr/*.h)
file(GLOB SOURCES_H ${CMAKE_CURRENT_SOURCE_DIR}/src/*.h)
file(GLOB SOURCES_C ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)

if (DEFINED ENV{EMSCRIPTEN_BUILD})
    set(CMAKE_SHARED_LIBRARY_SUFFIX .bc)
endif()

add_library(peacemakr-core-crypto SHARED ${SOURCES_C} ${SOURCES_H} ${INCLUDES})
add_library(peacemakr-core-crypto_static STATIC ${SOURCES_C} ${SOURCES_H} ${INCLUDES})
add_definitions(-DOPENSSL_MIN_API=0x10100000L)
target_include_directories(peacemakr-core-crypto
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/peacemakr>
               $<INSTALL_INTERFACE:include>
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_include_directories(peacemakr-core-crypto_static
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/peacemakr>
               $<INSTALL_INTERFACE:include>
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Compile core crypto lib under asan if we're running in debug mode
option(ASAN "Turn off ASAN" ON)
if(("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang") AND ((CMAKE_BUILD_TYPE MATCHES DEBUG) OR (CMAKE_BUILD_TYPE MATCHES Debug)))
    if (ASAN)
        message(STATUS "Setting AddressSanitizer for Debug build")
        target_compile_options(peacemakr-core-crypto PUBLIC -fsanitize=address -fno-omit-frame-pointer)
        target_link_libraries(peacemakr-core-crypto PUBLIC -fsanitize=address)
        target_compile_options(peacemakr-core-crypto_static PUBLIC -fsanitize=address -fno-omit-frame-pointer)
        target_link_libraries(peacemakr-core-crypto_static PUBLIC -fsanitize=address)
    endif()
endif()

target_link_libraries(peacemakr-core-crypto
        PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(peacemakr-core-crypto_static
        PRIVATE OpenSSL::SSL OpenSSL::Crypto)

if (UNIX AND NOT APPLE)
    set(THREADS_PREFER_PTHREAD_FLAG TRUE)
    find_package(Threads)
    target_link_libraries(peacemakr-core-crypto PRIVATE dl Threads::Threads)
    target_link_libraries(peacemakr-core-crypto_static PRIVATE dl Threads::Threads)
endif()

if (STATIC_LIBC)
    if (APPLE)
        # Apple doesn't support linking static libc
    else()
        target_link_libraries(peacemakr-core-crypto PRIVATE -static-libgcc -Wl,-static c)
        target_link_libraries(peacemakr-core-crypto_static PRIVATE -static-libgcc -Wl,-static c)
    endif()
endif()

set_target_properties(peacemakr-core-crypto PROPERTIES
        PUBLIC_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/include/peacemakr/crypto.h;${CMAKE_CURRENT_SOURCE_DIR}/include/peacemakr/random.h"
)

set_target_properties(peacemakr-core-crypto_static PROPERTIES
        PUBLIC_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/include/peacemakr/crypto.h;${CMAKE_CURRENT_SOURCE_DIR}/include/peacemakr/random.h"
)

if ((CMAKE_BUILD_TYPE MATCHES RELEASE) OR (CMAKE_BUILD_TYPE MATCHES Release))
    message(STATUS "Stripping library of dead symbols")
    if (APPLE)
        target_link_options(peacemakr-core-crypto PRIVATE -Wl,-dead_strip)
        target_link_options(peacemakr-core-crypto_static PRIVATE -Wl,-dead_strip)

        add_custom_command(TARGET peacemakr-core-crypto POST_BUILD
                COMMAND ${CMAKE_STRIP} -x $<TARGET_FILE:peacemakr-core-crypto>)
        add_custom_command(TARGET peacemakr-core-crypto_static POST_BUILD
                COMMAND ${CMAKE_STRIP} -x $<TARGET_FILE:peacemakr-core-crypto>)
    else()
        target_link_options(peacemakr-core-crypto PRIVATE -Wl,--gc-sections)
        target_link_options(peacemakr-core-crypto_static PRIVATE -Wl,--gc-sections)

        add_custom_command(TARGET peacemakr-core-crypto POST_BUILD
                COMMAND ${CMAKE_STRIP} $<TARGET_FILE:peacemakr-core-crypto>)
        add_custom_command(TARGET peacemakr-core-crypto_static POST_BUILD
                COMMAND ${CMAKE_STRIP} $<TARGET_FILE:peacemakr-core-crypto>)
    endif()
endif ()

install(TARGETS peacemakr-core-crypto
        EXPORT peacemakr-core-crypto-targets
        LIBRARY DESTINATION lib
        PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_PREFIX}/include/peacemakr"
        COMPONENT dev
)

install(TARGETS peacemakr-core-crypto_static
        EXPORT peacemakr-core-crypto-targets
        LIBRARY DESTINATION lib
        PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_PREFIX}/include/peacemakr"
        COMPONENT dev
)

if (BUILD_TESTS)
    add_subdirectory(test)
endif(BUILD_TESTS)

set(ALL_C_SOURCE_FILES ${SOURCES_C} ${SOURCES_H} ${INCLUDES} ${ALL_C_SOURCE_FILES} PARENT_SCOPE)
