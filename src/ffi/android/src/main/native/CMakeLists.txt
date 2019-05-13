add_library(peacemakr-core-crypto-jni SHARED crypto-jni.c)

if (APPLE)
    target_link_libraries(peacemakr-core-crypto-jni
            PRIVATE peacemakr-core-crypto)
else()
    target_link_libraries(peacemakr-core-crypto-jni
            PRIVATE peacemakr-core-crypto -ldl)
endif()

target_link_libraries(peacemakr-core-crypto-jni PUBLIC android log)