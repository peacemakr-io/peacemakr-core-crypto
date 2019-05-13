add_library(peacemakr-core-crypto-jni SHARED crypto-jni.c)

if (APPLE)
    target_link_libraries(peacemakr-core-crypto-jni
            PUBLIC -Wl,-all_load peacemakr-core-crypto -Wl,-noall_load)
else()
    target_link_libraries(peacemakr-core-crypto-jni
            PUBLIC -Wl,--whole-archive peacemakr-core-crypto -Wl,--no-whole-archive -ldl)
endif()

target_link_libraries(peacemakr-core-crypto-jni PUBLIC android log)