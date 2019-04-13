#
# Created by Aman LaChapelle on 7/20/18.
#
# peacemakr-core-crypto
# Copyright (c) 2018 peacemakr
# Full license at peacemakr-core-crypto/LICENSE.txt
#

enable_testing()
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} -j4 --schedule-random -V)

if (UNIX AND NOT APPLE)
    find_package(PkgConfig)
    pkg_check_modules(LIBBSD REQUIRED libbsd)
endif()

function(add_ctest test_name)
    add_executable(test_${test_name} EXCLUDE_FROM_ALL ${CMAKE_CURRENT_SOURCE_DIR}/${test_name}.c)

    if((CMAKE_BUILD_TYPE MATCHES DEBUG) OR (CMAKE_BUILD_TYPE MATCHES Debug))
        target_compile_options(test_${test_name} PUBLIC -fsanitize=address -g -Os -fPIC -fstack-protector-strong -fno-omit-frame-pointer -Wall)
        target_link_libraries(test_${test_name} PRIVATE -fsanitize=address)
    endif()

    target_link_libraries(test_${test_name} PRIVATE peacemakr-core-crypto ${LIBBSD_LIBRARIES})
    target_include_directories(test_${test_name} PRIVATE ${CMAKE_SOURCE_DIR}/src/core/include ${LIBBSD_INCLUDE_DIRS})
    set(ALL_C_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/${test_name}.c ${ALL_C_SOURCE_FILES} PARENT_SCOPE)

    add_test(NAME test_${test_name} COMMAND ${CMAKE_CURRENT_BINARY_DIR}/test_${test_name})
    add_dependencies(check test_${test_name})
endfunction(add_ctest)

add_ctest(encrypt_symmetric)
add_ctest(encrypt_asymmetric)
add_ctest(encrypt_asymmetric_from_pem)
add_ctest(encrypt_asymmetric_gen_pem)
add_ctest(serialize)
add_ctest(big_message)
add_ctest(sign)
add_ctest(garbage)
add_ctest(dh_keygen)
add_ctest(encrypt_dh_pem)

enable_language(CXX)
set(CMAKE_CXX_STANDARD 11)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    if (APPLE)
        execute_process(COMMAND mkdir -p CORPUS WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
    endif(APPLE)

    add_executable(test_fuzz EXCLUDE_FROM_ALL ${CMAKE_CURRENT_SOURCE_DIR}/fuzz.cpp)
    target_compile_options(test_fuzz PUBLIC -g -fsanitize=fuzzer,address)
    target_link_libraries(test_fuzz PRIVATE peacemakr-core-crypto-cpp ${LIBBSD_LIBRARIES} -fsanitize=fuzzer,address)
    target_include_directories(test_fuzz PRIVATE ${CMAKE_SOURCE_DIR}/src/core/include ${LIBBSD_INCLUDE_DIRS})
endif()
