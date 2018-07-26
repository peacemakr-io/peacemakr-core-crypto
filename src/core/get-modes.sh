#!/bin/bash

openssl ciphers \
| tr ":" "\n" \
| awk '{print "\""$0"\""}' \
| sed -e '$!s/$/,/' \
| tee ${1}/src/OpenSSLModeStrings.def \
| sed -e 's/-/_/g' \
| tr -d "\"" \
> ${1}/include/OpenSSLModes.def
