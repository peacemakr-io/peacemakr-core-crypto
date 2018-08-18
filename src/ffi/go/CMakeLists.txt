#add_custom_target(core-crypto-go
#        COMMAND export LD_LIBRARY_PATH="${CMAKE_BINARY_DIR}/src/core:$ENV{LD_LIBRARY_PATH}"
#        COMMAND go build .
#        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/peacemakr_core_crypto
#)
#
#if (BUILD_TESTS)
#    add_custom_target(test_core-crypto-go
#            COMMAND export LD_LIBRARY_PATH="${CMAKE_BINARY_DIR}/src/core:$ENV{LD_LIBRARY_PATH}"
#            COMMAND go test .
#            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/peacemakr_core_crypto
#    )
#    add_dependencies(check test_core-crypto-go)
#endif(BUILD_TESTS)