include(${CMAKE_SOURCE_DIR}/cmake/AddPybind11.cmake)

file(GLOB SOURCES src/*.cpp)
file(GLOB HEADERS src/*.h)

find_package(Python 3 COMPONENTS Development Interpreter)

get_target_property(CPP_SOURCE_DIR peacemakr-core-crypto-cpp SOURCE_DIR)

pybind11_add_module(peacemakr_core_crypto_python ${SOURCES} ${HEADERS})
target_link_libraries(peacemakr_core_crypto_python PRIVATE peacemakr-core-crypto-cpp)
target_include_directories(peacemakr_core_crypto_python PRIVATE ${CPP_SOURCE_DIR}/include)

add_custom_target(python-test
        COMMAND ${CMAKE_COMMAND} -E env PYTHONPATH=${CMAKE_CURRENT_BINARY_DIR}:$ENV{PYTHONPATH}
        ${Python_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test.py
        DEPENDS peacemakr_core_crypto_python
)

add_dependencies(check python-test)

if (NOT DEFINED PYTHON_INSTALL_DIR)
    install(TARGETS peacemakr_core_crypto_python
            LIBRARY DESTINATION ${Python_SITEARCH}
            COMPONENT dev
    )
else()
    message("Installing in ${PYTHON_INSTALL_DIR}")
    install(TARGETS peacemakr_core_crypto_python
            LIBRARY DESTINATION ${PYTHON_INSTALL_DIR}
            COMPONENT dev
    )
endif()


