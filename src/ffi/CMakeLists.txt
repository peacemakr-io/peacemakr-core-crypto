set(CORE_LIB_INCLUDE ${CMAKE_SOURCE_DIR}/src/core/include)
set(CORE_LIB_DIR ${CMAKE_BINARY_DIR}/src/core)

option(PEACEMAKR_BUILD_GO "Whether to build the Golang bindings" ON)
if (PEACEMAKR_BUILD_GO)
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/go/crypto.go.in ${CMAKE_CURRENT_SOURCE_DIR}/go/src/peacemakr/crypto/crypto.go @ONLY)

    install(CODE
            "
    file(REMOVE ${CMAKE_SOURCE_DIR}/src/ffi/go/src/peacemakr/crypto/crypto.go)

    set(CORE_LIB_INCLUDE ${CMAKE_INSTALL_PREFIX}/include)
    set(CORE_LIB_DIR ${CMAKE_INSTALL_PREFIX}/lib)
    set(OPENSSL_INCLUDE_DIR /usr/include)

    configure_file(${CMAKE_SOURCE_DIR}/src/ffi/go/crypto.go.in ${CMAKE_SOURCE_DIR}/src/ffi/go/src/peacemakr/crypto/crypto.go @ONLY)
    ")
endif (PEACEMAKR_BUILD_GO)

# Swift-specific stuff #####
option(PEACEMAKR_BUILD_IOS "Whether to build the iOS bindings" ON)

if (PEACEMAKR_BUILD_IOS)
    set(SOURCE_CMAKE_DIR ${CMAKE_SOURCE_DIR})
    set(OPENSSL_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/swift/openssl/openssl-build)
    set(OPENSSL_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/swift/openssl/openssl-build/lib)
    set(CMAKE_IOS_TOOLCHAIN_FILE ${CMAKE_SOURCE_DIR}/cmake/iOS.cmake)
    set(FAT_CORE_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/swift/libCoreCrypto/lib)
    set(CORE_LIB_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/swift/libCoreCrypto/include)

    configure_file(${CMAKE_SOURCE_DIR}/src/ffi/swift/module.map.in ${CMAKE_SOURCE_DIR}/src/ffi/swift/CoreCrypto/CoreCrypto/module.map @ONLY)
    configure_file(${CMAKE_SOURCE_DIR}/src/ffi/swift/build-core-crypto.sh.in ${CMAKE_SOURCE_DIR}/src/ffi/swift/libCoreCrypto/build-core-crypto.sh @ONLY)

    install(CODE
            "
    file(REMOVE ${CMAKE_SOURCE_DIR}/src/ffi/swift/CoreCrypto/CoreCrypto/module.map)

    set(CORE_LIB_INCLUDE ${CMAKE_INSTALL_PREFIX}/include)
    set(CORE_LIB_DIR ${CMAKE_INSTALL_PREFIX}/lib)
    set(FAT_CORE_LIB_DIR ${CMAKE_INSTALL_PREFIX}/lib)

    configure_file(${CMAKE_SOURCE_DIR}/src/ffi/swift/module.map.in ${CMAKE_SOURCE_DIR}/src/ffi/swift/CoreCrypto/CoreCrypto/module.map @ONLY)
    ")
endif(PEACEMAKR_BUILD_IOS)

# C++-specific stuff #####
option(PEACEMAKR_BUILD_CPP "Whether to build the C++ bindings" ON)

if (PEACEMAKR_BUILD_CPP)
    add_subdirectory(cpp)
endif(PEACEMAKR_BUILD_CPP)

set(ALL_C_SOURCE_FILES ${SOURCES_C} ${SOURCES_H} ${INCLUDES} ${ALL_C_SOURCE_FILES} PARENT_SCOPE)

# Web-specfic stuff #####
option(PEACEMAKR_BUILD_WEB "Whether to build the WASM bindings" ON)

if (PEACEMAKR_BUILD_WEB)
    set(SOURCE_CMAKE_DIR ${CMAKE_SOURCE_DIR})
    set(OPENSSL_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/web/openssl/build)
    set(OPENSSL_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/web/openssl/build/lib)
    configure_file(${CMAKE_SOURCE_DIR}/src/ffi/web/build-core-crypto.sh.in ${CMAKE_SOURCE_DIR}/src/ffi/web/build-core-crypto.sh @ONLY)
endif()

