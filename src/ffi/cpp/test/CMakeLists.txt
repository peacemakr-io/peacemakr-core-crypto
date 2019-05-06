enable_language(CXX)
set(CMAKE_CXX_STANDARD 11)

add_executable(test_cpp EXCLUDE_FROM_ALL ${CMAKE_CURRENT_SOURCE_DIR}/test.cpp)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    target_compile_options(test_cpp PUBLIC -fsanitize=address -g -Os -fPIC -fstack-protector-strong -fno-omit-frame-pointer -Wall)
    target_link_libraries(test_cpp PRIVATE -fsanitize=address)
else()
    target_compile_options(test_cpp PUBLIC -g -Os -fPIC -fstack-protector-strong -fno-omit-frame-pointer -Wall)
    target_link_libraries(test_cpp PRIVATE)
endif()

target_link_libraries(test_cpp PRIVATE peacemakr-core-crypto-cpp ${LIBBSD_LIBRARIES})
target_include_directories(test_cpp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include ${LIBBSD_INCLUDE_DIRS})
set(ALL_C_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/test.cpp ${ALL_C_SOURCE_FILES} PARENT_SCOPE)

add_test(NAME test_cpp COMMAND ${CMAKE_CURRENT_BINARY_DIR}/test_cpp)
add_dependencies(check test_cpp)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    if (APPLE)
        execute_process(COMMAND mkdir -p CORPUS WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
    endif(APPLE)

    add_executable(test_fuzz EXCLUDE_FROM_ALL ${CMAKE_CURRENT_SOURCE_DIR}/fuzz.cpp)
    target_compile_options(test_fuzz PUBLIC -g -fsanitize=fuzzer,address)
    target_link_libraries(test_fuzz PRIVATE peacemakr-core-crypto-cpp ${LIBBSD_LIBRARIES} -fsanitize=fuzzer,address)
    target_include_directories(test_fuzz PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../include ${LIBBSD_INCLUDE_DIRS})
endif()