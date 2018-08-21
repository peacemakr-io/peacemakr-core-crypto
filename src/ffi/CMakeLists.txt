# install swift modulemap
set(HEADER_INCLUDE_PATH ${CMAKE_INSTALL_PREFIX})
configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/swift/module.map.in
        ${CMAKE_CURRENT_SOURCE_DIR}/swift/PeacemakrCoreCrypto/module.map
        @ONLY
)
