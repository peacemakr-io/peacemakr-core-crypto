#
# Created by Aman LaChapelle on 7/20/18.
#
# peacemakr-core-crypto
# Copyright (c) 2018 peacemakr
# Full license at peacemakr-core-crypto/LICENSE.txt
#

if (NOT __CLANG_FORMAT_INCLUDED)
    set(__CLANG_FORMAT_INCLUDED TRUE)

    find_program(CLANG_FORMAT "clang-format")
    if(CLANG_FORMAT)
        add_custom_target(
                clang-format
                COMMAND ${CLANG_FORMAT}
                -i
                -style=llvm
                ${ALL_C_SOURCE_FILES}
        )
    endif(CLANG_FORMAT)
endif (NOT __CLANG_FORMAT_INCLUDED)