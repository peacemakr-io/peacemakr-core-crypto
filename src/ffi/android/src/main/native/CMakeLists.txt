if (NOT DEFINED ANDROID_ABI)
    find_package(JNI)
endif (NOT DEFINED ANDROID_ABI)

set(ALL_C_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/crypto-jni.c ${ALL_C_SOURCE_FILES} PARENT_SCOPE)

add_library(peacemakr-core-crypto-jni SHARED ${CMAKE_CURRENT_SOURCE_DIR}/crypto-jni.c)
target_include_directories(peacemakr-core-crypto-jni PRIVATE ${JNI_INCLUDE_DIRS})

if (APPLE)
    target_link_libraries(peacemakr-core-crypto-jni
            PRIVATE peacemakr-core-crypto)
else()
    target_link_libraries(peacemakr-core-crypto-jni
            PRIVATE peacemakr-core-crypto -ldl)
endif()

if (NOT DEFINED ANDROID_ABI)
    target_link_libraries(peacemakr-core-crypto-jni PUBLIC android log)
endif (NOT DEFINED ANDROID_ABI)