cmake_minimum_required(VERSION 3.5)
project(peacemakr_sdk_core)

file(GLOB INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp)
file(GLOB SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)

add_library(peacemakr-sdk-core ${SOURCES} ${INCLUDES})
target_include_directories(peacemakr-sdk-core
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(peacemakr-sdk-core PUBLIC OpenSSL::SSL)