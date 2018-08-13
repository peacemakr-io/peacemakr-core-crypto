#
# Created by Aman LaChapelle on 7/20/18.
#
# peacemakr-core-crypto
# Copyright (c) 2018 peacemakr
# Full license at peacemakr-core-crypto/LICENSE.txt
#

enable_testing()
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} -V)

if (UNIX AND NOT APPLE)
    find_package(PkgConfig)
    pkg_check_modules(LIBBSD REQUIRED libbsd)
endif()

function(add_ptest test_name)
    add_executable(test_${test_name} EXCLUDE_FROM_ALL ${CMAKE_CURRENT_SOURCE_DIR}/${test_name}.c)
    target_link_libraries(test_${test_name} PRIVATE peacemakr-core-crypto ${LIBBSD_LIBRARIES})
    target_include_directories(test_${test_name} PRIVATE ${CMAKE_SOURCE_DIR}/src/core/include ${LIBBSD_INCLUDE_DIRS})

    add_test(NAME test_${test_name} COMMAND ${CMAKE_CURRENT_BINARY_DIR}/test_${test_name})
    add_dependencies(check test_${test_name})
endfunction(add_ptest)

add_ptest(encrypt_symmetric)
add_ptest(encrypt_asymmetric) # NOT CURRENTLY WORKING...?
