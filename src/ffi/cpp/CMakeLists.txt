enable_language(CXX)
set(CMAKE_CXX_STANDARD 11)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions")

file(GLOB SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

add_library(peacemakr-core-crypto-cpp SHARED ${SOURCES})
target_link_libraries(peacemakr-core-crypto-cpp PUBLIC peacemakr-core-crypto)
target_include_directories(peacemakr-core-crypto-cpp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

if (ASAN)
    message(STATUS "Setting AddressSanitizer for Debug build - C++")
    target_compile_options(peacemakr-core-crypto-cpp PUBLIC -fsanitize=address -fno-omit-frame-pointer)
    target_link_libraries(peacemakr-core-crypto-cpp PUBLIC -fsanitize=address)
endif()

set_target_properties(peacemakr-core-crypto-cpp PROPERTIES PUBLIC_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/include/peacemakr/crypto.hpp")

install(TARGETS peacemakr-core-crypto-cpp
        EXPORT peacemakr-core-crypto-targets
        LIBRARY DESTINATION lib
        PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_PREFIX}/include/peacemakr"
        COMPONENT dev
)

if (BUILD_TESTS)
    add_subdirectory(test)
endif(BUILD_TESTS)

set(ALL_C_SOURCE_FILES ${SOURCES} ${CMAKE_CURRENT_SOURCE_DIR}/include/peacemakr/crypto.hpp ${ALL_C_SOURCE_FILES} PARENT_SCOPE)
