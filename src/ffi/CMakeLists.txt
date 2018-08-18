# install swift modulemap
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/swift/module.map.in ${CMAKE_CURRENT_BINARY_DIR}/swift/module.map @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/swift/module.map DESTINATION modules/peacemakr)

