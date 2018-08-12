#
# Created by Aman LaChapelle on 7/20/18.
#
# peacemakr-core-crypto
# Copyright (c) 2018 peacemakr
# Full license at peacemakr-core-crypto/LICENSE.txt
#

enable_testing()
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} -V)

function(add_test test_name)
    add_executable(test_${test_name} ${CMAKE_CURRENT_SOURCE_DIR}/${test_name}.c)
    target_link_libraries(test_${test_name} PRIVATE peacemakr-core-crypto)
    target_include_directories(test_${test_name} PRIVATE ${CMAKE_SOURCE_DIR}/src/core/include)

    add_dependencies(check test_${test_name})
endfunction(add_test)

add_test(encrypt_symmetric)
#add_test(encrypt_asymmetric) # NOT CURRENTLY WORKING...?
