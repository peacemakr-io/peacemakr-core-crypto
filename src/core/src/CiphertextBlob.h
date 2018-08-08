//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#ifndef PEACEMAKR_CORE_CRYPTO_CIPHERTEXT_H
#define PEACEMAKR_CORE_CRYPTO_CIPHERTEXT_H

#include <crypto.h>
#include <stdint.h>

typedef struct CiphertextBlob ciphertext_blob_t;

ciphertext_blob_t *CiphertextBlob_new(crypto_config_t cfg, size_t iv_len,
                                      size_t tag_len, size_t aad_len,
                                      size_t ciphertext_len, size_t digest_len);

void CiphertextBlob_free(ciphertext_blob_t *ciphertext);

#endif // PEACEMAKR_CORE_CRYPTO_CIPHERTEXT_H
