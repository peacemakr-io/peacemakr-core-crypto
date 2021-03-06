if (NOT __ADD_PYBIND11_INCLUDED)
    set(__ADD_PYBIND11_INCLUDED TRUE)

    include(FetchContent)
    FetchContent_Declare(
            pybind11
            GIT_REPOSITORY https://github.com/pybind/pybind11.git
            GIT_TAG        v2.4.1
    )

    FetchContent_GetProperties(pybind11)
    if(NOT pybind11_POPULATED)
        FetchContent_Populate(pybind11)
        add_subdirectory(${pybind11_SOURCE_DIR} ${pybind11_BINARY_DIR})
    endif()
endif()