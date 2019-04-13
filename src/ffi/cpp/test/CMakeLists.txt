add_executable(test_cpp EXCLUDE_FROM_ALL ${CMAKE_CURRENT_SOURCE_DIR}/test.cpp)

if((CMAKE_BUILD_TYPE MATCHES DEBUG) OR (CMAKE_BUILD_TYPE MATCHES Debug))
    target_compile_options(test_cpp PUBLIC -fsanitize=address -g -Os -fPIC -fstack-protector-strong -fno-omit-frame-pointer -Wall)
    target_link_libraries(test_cpp PRIVATE -fsanitize=address)
endif()

target_link_libraries(test_cpp PRIVATE peacemakr-core-crypto-cpp ${LIBBSD_LIBRARIES})
target_include_directories(test_cpp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include ${LIBBSD_INCLUDE_DIRS})
set(ALL_C_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/test.cpp ${ALL_C_SOURCE_FILES} PARENT_SCOPE)

add_test(NAME test_cpp COMMAND ${CMAKE_CURRENT_BINARY_DIR}/test_cpp)
add_dependencies(check test_cpp)