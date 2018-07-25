//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include <stdint.h>

#include <openssl/evp.h>

enum Mode {
#include "OpenSSLModes.def"
};

// use EVP_get_cipherbyname()
const char *evp_cipher_names[] = {
#include "OpenSSLModeStrings.def"
};

// OpenSSL does its own padding by default so padding is always PKCS#5

struct EncryptedBlob {
  uint8_t m_version_[3];
};
