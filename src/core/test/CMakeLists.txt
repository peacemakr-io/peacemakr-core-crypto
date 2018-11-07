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

function(add_ctest test_name)
    add_executable(test_${test_name} EXCLUDE_FROM_ALL ${CMAKE_CURRENT_SOURCE_DIR}/${test_name}.c)
    target_link_libraries(test_${test_name} PRIVATE peacemakr-core-crypto ${LIBBSD_LIBRARIES})
    target_include_directories(test_${test_name} PRIVATE ${CMAKE_SOURCE_DIR}/src/core/include ${LIBBSD_INCLUDE_DIRS})

    add_test(NAME test_${test_name} COMMAND ${CMAKE_CURRENT_BINARY_DIR}/test_${test_name})
    add_dependencies(check test_${test_name})
endfunction(add_ctest)

add_ctest(encrypt_symmetric)
add_ctest(encrypt_asymmetric)
add_ctest(encrypt_asymmetric_from_pem)
add_ctest(serialize)
add_ctest(big_message)

enable_language(CXX)
set(CMAKE_CXX_STANDARD 11)

add_executable(test_cpp EXCLUDE_FROM_ALL ${CMAKE_CURRENT_SOURCE_DIR}/test.cpp)
target_link_libraries(test_cpp PRIVATE peacemakr-core-crypto-cpp ${LIBBSD_LIBRARIES})
target_include_directories(test_cpp PRIVATE ${CMAKE_SOURCE_DIR}/src/core/include ${LIBBSD_INCLUDE_DIRS})
add_test(NAME test_cpp COMMAND ${CMAKE_CURRENT_BINARY_DIR}/test_cpp)
add_dependencies(check test_cpp)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    if (APPLE)
        execute_process(COMMAND mkdir -p CORPUS WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
    endif(APPLE)

    add_executable(test_fuzz EXCLUDE_FROM_ALL ${CMAKE_CURRENT_SOURCE_DIR}/fuzz.cpp)
    target_compile_options(test_fuzz PUBLIC -g -fsanitize=fuzzer,address)
    target_link_libraries(test_fuzz PRIVATE peacemakr-core-crypto-cpp ${LIBBSD_LIBRARIES} -fsanitize=fuzzer,address)
    target_include_directories(test_fuzz PRIVATE ${CMAKE_SOURCE_DIR}/src/core/include ${LIBBSD_INCLUDE_DIRS})
endif()
