# install swift modulemap

set(HEADER_INCLUDE_PATH ${CMAKE_SOURCE_DIR}/src/core)
set(INCLUDE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/swift/PeacemakrCoreCrypto)
set(CORE_LIB_DIR ${CMAKE_BINARY_DIR}/src/core)

configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/swift/module.map.in
        ${CMAKE_CURRENT_SOURCE_DIR}/swift/PeacemakrCoreCrypto/module.map
        @ONLY
)
configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/swift/run_tests.sh.in
        ${CMAKE_CURRENT_SOURCE_DIR}/swift/PeacemakrCoreCrypto/run_tests.sh
        @ONLY
)

# TODO: install the module.map with the correct header path
