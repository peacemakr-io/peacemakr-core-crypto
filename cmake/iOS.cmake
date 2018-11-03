# Toolchain config for iOS.
#
# Usage:
# mkdir build; cd build
# cmake ..; make
# mkdir ios; cd ios
# cmake -DLLVM_IOS_TOOLCHAIN_DIR=/path/to/ios/ndk \
#   -DCMAKE_TOOLCHAIN_FILE=../../cmake/platforms/iOS.cmake ../..
# make <target>

SET(CMAKE_SYSTEM_NAME Darwin)
SET(CMAKE_SYSTEM_VERSION 1)
SET(CMAKE_CXX_COMPILER_WORKS True)
SET(CMAKE_C_COMPILER_WORKS True)
set (UNIX True)
set (APPLE True)
set (IOS True)

set(CMAKE_C_OSX_COMPATIBILITY_VERSION_FLAG "-compatibility_version ")
set(CMAKE_C_OSX_CURRENT_VERSION_FLAG "-current_version ")
set(CMAKE_CXX_OSX_COMPATIBILITY_VERSION_FLAG "${CMAKE_C_OSX_COMPATIBILITY_VERSION_FLAG}")
set(CMAKE_CXX_OSX_CURRENT_VERSION_FLAG "${CMAKE_C_OSX_CURRENT_VERSION_FLAG}")

message("${IOS_PLATFORM}")

IF (NOT DEFINED IOS_MIN_TARGET)
    set(IOS_MIN_TARGET 8.1)
ENDIF()

if ("${IOS_PLATFORM}" STREQUAL "OS")
    SET(PLATFORM_NAME iphoneos)
elseif ("${IOS_PLATFORM}" STREQUAL "SIMULATOR")
    SET(PLATFORM_NAME iphonesimulator)
else()
    SET(PLATFORM_NAME iphoneos)
endif ()

IF("$ENV{RC_APPLETV}" STREQUAL "YES")
    MESSAGE(STATUS "Building for tvos")
    STRING(TOLOWER $ENV{RC_APPLETV_PLATFORM_NAME} PLATFORM_NAME)
ENDIF()

IF("$ENV{RC_WATCH}" STREQUAL "YES")
    MESSAGE(STATUS "Building for watchos")
    STRING(TOLOWER $ENV{RC_WATCH_PLATFORM_NAME} PLATFORM_NAME)
ENDIF()

IF(NOT DEFINED ENV{SDKROOT})
    execute_process(COMMAND xcodebuild -version -sdk ${PLATFORM_NAME} Path
            OUTPUT_VARIABLE SDKROOT
            ERROR_QUIET
            OUTPUT_STRIP_TRAILING_WHITESPACE)
ELSE()
    execute_process(COMMAND xcodebuild -version -sdk $ENV{SDKROOT} Path
            OUTPUT_VARIABLE SDKROOT
            ERROR_QUIET
            OUTPUT_STRIP_TRAILING_WHITESPACE)
ENDIF()

IF(NOT EXISTS ${SDKROOT})
    MESSAGE(FATAL_ERROR "SDKROOT could not be detected!")
ENDIF()

SET(IOS_COMMON_FLAGS "-isysroot ${SDKROOT} -m${PLATFORM_NAME}-version-min=${IOS_MIN_TARGET} -fembed-bitcode -fvisibility=hidden -fvisibility-inlines-hidden")

SET(CMAKE_C_FLAGS "${IOS_COMMON_FLAGS}" CACHE STRING "toolchain_cflags" FORCE)
SET(CMAKE_CXX_FLAGS "${IOS_COMMON_FLAGS}" CACHE STRING "toolchain_cxxflags" FORCE)
SET(CMAKE_LINK_FLAGS "${IOS_COMMON_FLAGS}" CACHE STRING "toolchain_linkflags" FORCE)

set(CMAKE_OSX_SYSROOT ${SDKROOT})

IF(NOT CMAKE_C_COMPILER)
    execute_process(COMMAND xcrun -sdk ${SDKROOT} -find clang
            OUTPUT_VARIABLE CMAKE_C_COMPILER
            ERROR_QUIET
            OUTPUT_STRIP_TRAILING_WHITESPACE)
    message(STATUS "Using c compiler ${CMAKE_C_COMPILER}")
ENDIF()

IF(NOT CMAKE_CXX_COMPILER)
    execute_process(COMMAND xcrun -sdk ${SDKROOT} -find clang++
            OUTPUT_VARIABLE CMAKE_CXX_COMPILER
            ERROR_QUIET
            OUTPUT_STRIP_TRAILING_WHITESPACE)
    message(STATUS "Using c compiler ${CMAKE_CXX_COMPILER}")
ENDIF()

IF(NOT CMAKE_AR)
    execute_process(COMMAND xcrun -sdk ${SDKROOT} -find ar
            OUTPUT_VARIABLE CMAKE_AR_val
            ERROR_QUIET
            OUTPUT_STRIP_TRAILING_WHITESPACE)
    SET(CMAKE_AR ${CMAKE_AR_val} CACHE FILEPATH "Archiver")
    message(STATUS "Using ar ${CMAKE_AR}")
ENDIF()

IF(NOT CMAKE_RANLIB)
    execute_process(COMMAND xcrun -sdk ${SDKROOT} -find ranlib
            OUTPUT_VARIABLE CMAKE_RANLIB_val
            ERROR_QUIET
            OUTPUT_STRIP_TRAILING_WHITESPACE)
    SET(CMAKE_RANLIB ${CMAKE_RANLIB_val} CACHE FILEPATH "Ranlib")
    message(STATUS "Using ranlib ${CMAKE_RANLIB}")
ENDIF()

# set the architecture for iOS
# TODO: should build for armv7s too?
if ("${IOS_PLATFORM}" STREQUAL "OS")
    set (IOS_ARCH arm64)
elseif ("${IOS_PLATFORM}" STREQUAL "SIMULATOR")
    set (IOS_ARCH x86_64)
    set (VALID_ARCHS x86_64)
endif ("${IOS_PLATFORM}" STREQUAL "OS")

set(CMAKE_OSX_ARCHITECTURES ${IOS_ARCH} CACHE string  "Build architecture for iOS")