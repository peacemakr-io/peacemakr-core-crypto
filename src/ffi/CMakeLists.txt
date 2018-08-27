set(CORE_LIB_INCLUDE ${CMAKE_SOURCE_DIR}/src/core/include)
set(CORE_LIB_DIR ${CMAKE_BINARY_DIR}/src/core)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/go/crypto.go.in ${CMAKE_CURRENT_SOURCE_DIR}/go/src/peacemakr/crypto/crypto.go @ONLY)

install(CODE
"
file(REMOVE ${CMAKE_SOURCE_DIR}/src/ffi/go/src/peacemakr/crypto/crypto.go)

set(CORE_LIB_INCLUDE ${CMAKE_INSTALL_PREFIX}/include)
set(CORE_LIB_DIR ${CMAKE_INSTALL_PREFIX}/lib)
set(OPENSSL_INCLUDE_DIR /usr/include)

configure_file(${CMAKE_SOURCE_DIR}/src/ffi/go/crypto.go.in ${CMAKE_SOURCE_DIR}/src/ffi/go/src/peacemakr/crypto/crypto.go @ONLY)
")
