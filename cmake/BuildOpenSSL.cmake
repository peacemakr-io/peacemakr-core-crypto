configure_file(${CMAKE_SOURCE_DIR}/cmake/build-openssl.sh.in ${CMAKE_SOURCE_DIR}/cmake/build-openssl.sh @ONLY)
add_custom_target(openssl-build ${CMAKE_SOURCE_DIR}/cmake/build-openssl.sh)
