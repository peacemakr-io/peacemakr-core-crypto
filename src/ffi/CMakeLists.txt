set(CORE_LIB_INCLUDE ${CMAKE_SOURCE_DIR}/src/core/include)
set(CORE_LIB_DIR ${CMAKE_BINARY_DIR}/src/core)

# Swift-specific stuff #####
option(PEACEMAKR_BUILD_IOS "Whether to build the iOS bindings" OFF)

if (PEACEMAKR_BUILD_IOS)
    set(SOURCE_CMAKE_DIR ${CMAKE_SOURCE_DIR})
    set(OPENSSL_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/swift/openssl/openssl-build)
    set(OPENSSL_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/swift/openssl/openssl-build/lib)
    set(CMAKE_IOS_TOOLCHAIN_FILE ${CMAKE_SOURCE_DIR}/cmake/iOS.cmake)
    set(FAT_CORE_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/swift/libCoreCrypto/lib)
    set(CORE_LIB_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/swift/libCoreCrypto/include)

    # configure_file(${CMAKE_SOURCE_DIR}/src/ffi/swift/module.map.in ${CMAKE_SOURCE_DIR}/src/ffi/swift/CoreCrypto/CoreCrypto/module.map @ONLY)
    configure_file(${CMAKE_SOURCE_DIR}/src/ffi/swift/build-core-crypto.sh.in ${CMAKE_SOURCE_DIR}/src/ffi/swift/libCoreCrypto/build-core-crypto.sh @ONLY)

    install(CODE
            "
    file(REMOVE ${CMAKE_SOURCE_DIR}/src/ffi/swift/CoreCrypto/CoreCrypto/module.map)

    set(CORE_LIB_INCLUDE ${CMAKE_INSTALL_PREFIX}/include)
    set(CORE_LIB_DIR ${CMAKE_INSTALL_PREFIX}/lib)
    set(FAT_CORE_LIB_DIR ${CMAKE_INSTALL_PREFIX}/lib)

    # configure_file(${CMAKE_SOURCE_DIR}/src/ffi/swift/module.map.in ${CMAKE_SOURCE_DIR}/src/ffi/swift/CoreCrypto/CoreCrypto/module.map @ONLY)
    ")
endif(PEACEMAKR_BUILD_IOS)

# Android-specific stuff #####
option(PEACEMAKR_BUILD_ANDROID "Whether to build the Android bindings" OFF)
if (PEACEMAKR_BUILD_ANDROID)
    message(FATAL_ERROR "Android build currently unsupported")
    set(OPENSSL_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/android/openssl/openssl-build/${ANDROID_ABI})
    set(OPENSSL_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/android/openssl/openssl-build/${ANDROID_ABI}/lib)

    add_subdirectory(android/src/main/native)
endif(PEACEMAKR_BUILD_ANDROID)

# Java-specific stuff #####
option(PEACEMAKR_BUILD_JAVA "Whether to build the Java bindings" OFF)
if (PEACEMAKR_BUILD_JAVA)
    add_subdirectory(java/src/main/c)
endif(PEACEMAKR_BUILD_JAVA)

# C++-specific, Python-specific, Web-specific stuff #####
option(PEACEMAKR_BUILD_CPP "Whether to build the C++ bindings" OFF)
option(PEACEMAKR_BUILD_PYTHON "Whether to build the Python bindings" OFF)

if (PEACEMAKR_BUILD_CPP OR PEACEMAKR_BUILD_PYTHON OR PEACEMAKR_BUILD_WEB)
    add_subdirectory(cpp)
endif()

if (PEACEMAKR_BUILD_PYTHON)
    add_subdirectory(python)
endif()

if (PEACEMAKR_BUILD_WEB)
    add_subdirectory(web)
endif()

set(ALL_C_SOURCE_FILES ${SOURCES_C} ${SOURCES_H} ${INCLUDES} ${ALL_C_SOURCE_FILES} PARENT_SCOPE)

