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
#include "peacemakr/crypto.h"

#include <stdint.h>

typedef struct CiphertextBlob ciphertext_blob_t;

ciphertext_blob_t *
ciphertext_blob_new(const crypto_config_t cfg, const size_t iv_len,
                    const size_t tag_len, const size_t aad_len,
                    const size_t ciphertext_len, const size_t digest_len);

ciphertext_blob_t *
ciphertext_blob_from_buffers(const crypto_config_t cfg, buffer_t *encrypted_key,
                             buffer_t *iv, buffer_t *tag, buffer_t *aad,
                             buffer_t *ciphertext, buffer_t *signature);

void ciphertext_blob_set_version(ciphertext_blob_t *ciphertext,
                                 uint32_t version);
const uint32_t ciphertext_blob_version(const ciphertext_blob_t *ciphertext);

void ciphertext_blob_init_iv(ciphertext_blob_t *ciphertext,
                             random_device_t *rng);

const buffer_t *ciphertext_blob_iv(const ciphertext_blob_t *ciphertext);

void ciphertext_blob_set_iv(ciphertext_blob_t *ciphertext,
                            const unsigned char *iv, size_t ivlen);
buffer_t *ciphertext_blob_mutable_encrypted_key(ciphertext_blob_t *ciphertext);
const buffer_t *
ciphertext_blob_encrypted_key(const ciphertext_blob_t *ciphertext);
buffer_t *ciphertext_blob_mutable_tag(ciphertext_blob_t *ciphertext);
const buffer_t *ciphertext_blob_tag(const ciphertext_blob_t *ciphertext);
buffer_t *ciphertext_blob_mutable_aad(ciphertext_blob_t *ciphertext);
const buffer_t *ciphertext_blob_aad(const ciphertext_blob_t *ciphertext);
buffer_t *ciphertext_blob_mutable_ciphertext(ciphertext_blob_t *ciphertext);
const buffer_t *ciphertext_blob_ciphertext(const ciphertext_blob_t *ciphertext);
buffer_t *ciphertext_blob_mutable_signature(ciphertext_blob_t *ciphertext);
const buffer_t *ciphertext_blob_signature(const ciphertext_blob_t *ciphertext);

const symmetric_cipher
ciphertext_blob_symm_cipher(const ciphertext_blob_t *ciphertext);
const asymmetric_cipher
ciphertext_blob_asymm_cipher(const ciphertext_blob_t *ciphertext);
const message_digest_algorithm
ciphertext_blob_digest_algo(const ciphertext_blob_t *ciphertext);
const encryption_mode
ciphertext_blob_encryption_mode(const ciphertext_blob_t *ciphertext);

void ciphertext_blob_set_digest_algo(ciphertext_blob_t *ciphertext,
                                     message_digest_algorithm digest);

bool ciphertext_blob_compare(const ciphertext_blob_t *lhs,
                             const ciphertext_blob_t *rhs);

#endif // PEACEMAKR_CORE_CRYPTO_CIPHERTEXT_H
