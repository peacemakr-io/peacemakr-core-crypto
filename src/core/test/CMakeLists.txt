#
# Created by Aman LaChapelle on 7/20/18.
#
# peacemakr-core-crypto
# Copyright (c) 2018 peacemakr
# Full license at peacemakr-core-crypto/LICENSE.txt
#

enable_testing()
add_custom_target(check-peacemakr-core-crypto COMMAND ${CMAKE_CTEST_COMMAND} -j4 --schedule-random -V)

file(GLOB HELPERS ${CMAKE_CURRENT_SOURCE_DIR}/utils/*)

set(ALL_C_SOURCE_FILES ${HELPERS} ${ALL_C_SOURCE_FILES} PARENT_SCOPE)

function(add_ctest test_name)
    add_executable(test_${test_name} EXCLUDE_FROM_ALL ${HELPERS} ${CMAKE_CURRENT_SOURCE_DIR}/${test_name}.c)
    # Inherits -fsanitize=address from peacemakr-core-crypto target
    target_compile_options(test_${test_name} PUBLIC -g -O0 -fPIC -fstack-protector-strong -Wall)

    target_link_libraries(test_${test_name} PRIVATE peacemakr-core-crypto ${ARGN})
    target_include_directories(test_${test_name} PRIVATE ${CMAKE_SOURCE_DIR}/src/core/include)
    set(ALL_C_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/${test_name}.c ${ALL_C_SOURCE_FILES} PARENT_SCOPE)

    add_test(NAME test_${test_name} COMMAND ${CMAKE_CURRENT_BINARY_DIR}/test_${test_name})
    add_dependencies(check-peacemakr-core-crypto test_${test_name})
endfunction(add_ctest)

add_definitions(-DPEACEMAKR_TEST_PEM_DIRECTORY="${CMAKE_CURRENT_SOURCE_DIR}/resources")

add_ctest(encrypt_symmetric)
add_ctest(encrypt_asymmetric)
add_ctest(encrypt_asymmetric_from_pem)
add_ctest(encrypt_asymmetric_gen_pem)
#add_ctest(get_key_from_cert)  # The certificate has expired
add_ctest(serialize)
add_ctest(big_message)
add_ctest(sign)
add_ctest(garbage)
add_ctest(dh_keygen)
add_ctest(encrypt_dh_pem)
add_ctest(regressions)

# This test doesn't work with a release version because it uses internal symbols
if ((CMAKE_BUILD_TYPE MATCHES DEBUG) OR (CMAKE_BUILD_TYPE MATCHES Debug))
    add_ctest(serialize_new_field OpenSSL::SSL OpenSSL::Crypto)
endif()

set(ALL_C_SOURCE_FILES ${ALL_C_SOURCE_FILES} PARENT_SCOPE)
