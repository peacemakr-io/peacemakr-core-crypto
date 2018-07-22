if (NOT __GLOG_INCLUDED)
    set(__GLOG_INCLUDED TRUE)

    include(ExternalProject)
    ExternalProject_Add(glog
            GIT_REPOSITORY    https://github.com/google/glog.git
            GIT_TAG           v0.3.5
            PREFIX            ${CMAKE_BINARY_DIR}/glog
            CMAKE_ARGS        -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/glog/glog-install
            INSTALL_DIR       ${CMAKE_BINARY_DIR}/glog/glog-install
    )

    ExternalProject_Get_Property(glog install_dir)

    add_library(glog::glog STATIC IMPORTED)
    set_property(TARGET glog::glog PROPERTY IMPORTED_LOCATION ${install_dir}/lib/libglog.a)
    add_dependencies(glog::glog glog)

    include_directories(glog::glog INTERFACE ${install_dir}/include)

endif (NOT __GLOG_INCLUDED)