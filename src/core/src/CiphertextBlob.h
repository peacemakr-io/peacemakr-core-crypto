//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#ifndef PEACEMAKR_CORE_CRYPTO_CIPHERTEXT_H
#define PEACEMAKR_CORE_CRYPTO_CIPHERTEXT_H

#include "Buffer.h"
#include "crypto.h"

#include <stdint.h>

typedef struct CiphertextBlob ciphertext_blob_t;

ciphertext_blob_t *CiphertextBlob_new(const crypto_config_t cfg,
                                      const size_t iv_len, const size_t tag_len,
                                      const size_t aad_len,
                                      const size_t ciphertext_len,
                                      const size_t digest_len);

ciphertext_blob_t *
CiphertextBlob_from_buffers(const crypto_config_t cfg, buffer_t *encrypted_key,
                            buffer_t *iv, buffer_t *tag, buffer_t *aad,
                            buffer_t *ciphertext, buffer_t *signature);

void CiphertextBlob_free(ciphertext_blob_t *ciphertext);

void CiphertextBlob_set_version(ciphertext_blob_t *ciphertext,
                                uint32_t version);
const uint32_t CiphertextBlob_version(const ciphertext_blob_t *ciphertext);

void CiphertextBlob_init_iv(ciphertext_blob_t *ciphertext,
                            random_device_t *rng);

const buffer_t *CiphertextBlob_iv(const ciphertext_blob_t *ciphertext);

void CiphertextBlob_set_iv(ciphertext_blob_t *ciphertext,
                           const unsigned char *iv, size_t ivlen);
buffer_t *CiphertextBlob_mutable_encrypted_key(ciphertext_blob_t *ciphertext);
const buffer_t *
CiphertextBlob_encrypted_key(const ciphertext_blob_t *ciphertext);
buffer_t *CiphertextBlob_mutable_tag(ciphertext_blob_t *ciphertext);
const buffer_t *CiphertextBlob_tag(const ciphertext_blob_t *ciphertext);
buffer_t *CiphertextBlob_mutable_aad(ciphertext_blob_t *ciphertext);
const buffer_t *CiphertextBlob_aad(const ciphertext_blob_t *ciphertext);
buffer_t *CiphertextBlob_mutable_ciphertext(ciphertext_blob_t *ciphertext);
const buffer_t *CiphertextBlob_ciphertext(const ciphertext_blob_t *ciphertext);
buffer_t *CiphertextBlob_mutable_signature(ciphertext_blob_t *ciphertext);
const buffer_t *CiphertextBlob_signature(const ciphertext_blob_t *ciphertext);

const symmetric_cipher
CiphertextBlob_symm_cipher(const ciphertext_blob_t *ciphertext);
const asymmetric_cipher
CiphertextBlob_asymm_cipher(const ciphertext_blob_t *ciphertext);
const message_digest_algorithm
CiphertextBlob_digest_algo(const ciphertext_blob_t *ciphertext);
const encryption_mode
CiphertextBlob_encryption_mode(const ciphertext_blob_t *ciphertext);

bool CiphertextBlob_compare(const ciphertext_blob_t *lhs,
                            const ciphertext_blob_t *rhs);

#endif // PEACEMAKR_CORE_CRYPTO_CIPHERTEXT_H
