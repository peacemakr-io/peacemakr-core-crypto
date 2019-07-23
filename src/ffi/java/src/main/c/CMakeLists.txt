if (NOT DEFINED ANDROID_ABI)
    find_package(JNI)
endif (NOT DEFINED ANDROID_ABI)

file(GLOB SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/*.c)

set(ALL_C_SOURCE_FILES ${SOURCES} ${ALL_C_SOURCE_FILES} PARENT_SCOPE)

add_library(peacemakr-core-crypto-jni SHARED ${SOURCES})
target_include_directories(peacemakr-core-crypto-jni PRIVATE ${JNI_INCLUDE_DIRS})

if (APPLE)
    target_link_libraries(peacemakr-core-crypto-jni
            PRIVATE peacemakr-core-crypto)
else()
    target_link_libraries(peacemakr-core-crypto-jni
            PRIVATE peacemakr-core-crypto -ldl -Wl,-rpath=$ORIGIN)
endif()

if (DEFINED ANDROID_ABI)
    target_link_libraries(peacemakr-core-crypto-jni PUBLIC android log)
endif (DEFINED ANDROID_ABI)

install(TARGETS peacemakr-core-crypto-jni
        EXPORT peacemakr-core-crypto-targets
        LIBRARY DESTINATION lib
        PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_PREFIX}/include/peacemakr"
        COMPONENT dev
)