//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#ifndef PEACEMAKR_CORE_CRYPTO_ENCRYPTEDBLOB_H
#define PEACEMAKR_CORE_CRYPTO_ENCRYPTEDBLOB_H

#include "CryptoContext.h"
#include "CryptoMemory.h"

typedef struct EncryptedBlob encrypted_blob_t;

encrypted_blob_t *EncryptedBlob_new(crypto_context_t *ctx, random_device_t *rng,
                                    secure_buffer_t *plaintext, secure_buffer_t *aad,
                                    secure_buffer_t *key);

secure_buffer_t *EncryptedBlob_read(crypto_context_t *ctx, encrypted_blob_t *blob);

void EncryptedBlob_free(encrypted_blob_t *blob);

#endif // PEACEMAKR_CORE_CRYPTO_ENCRYPTEDBLOB_H
