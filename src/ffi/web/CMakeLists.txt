get_target_property(CPP_SOURCE_DIR peacemakr-core-crypto-cpp SOURCE_DIR)

add_executable(corecrypto_js src/crypto.cpp)
set_target_properties(corecrypto_js PROPERTIES OUTPUT_NAME corecrypto)
target_compile_options(corecrypto_js PRIVATE -Oz -fno-rtti -fno-exceptions -DEMSCRIPTEN_HAS_UNBOUND_TYPE_NAMES=0)
target_link_libraries(corecrypto_js --bind -fno-rtti -fno-exceptions -Oz -sEXPORT_ES6=1 -sMODULARIZE=1 peacemakr-core-crypto-cpp)
target_include_directories(corecrypto_js PRIVATE ${CPP_SOURCE_DIR}/include)