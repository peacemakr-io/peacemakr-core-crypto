#
# Created by Aman LaChapelle on 7/20/18.
#
# peacemakr-core-crypto
# Copyright (c) 2018 peacemakr
# Full license at peacemakr-core-crypto/LICENSE.txt
#

if (NOT __CLANG_ANALYZER_INCLUDED)
    set(__CLANG_ANALYZER_INCLUDED TRUE)

    find_program(CLANG_ANALYZER "scan-build")
    if(CLANG_ANALYZER)
        add_custom_target(
                clang-analyzer
                COMMAND ${CLANG_ANALYZER}
                ${CMAKE_MAKE_PROGRAM}
        )
    endif(CLANG_ANALYZER)
endif (NOT __CLANG_ANALYZER_INCLUDED)
