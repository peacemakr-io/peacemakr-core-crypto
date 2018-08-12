//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include <Buffer.h>
#include <Logging.h>

#include "EVPHelper.h"
#include <crypto.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct CiphertextBlob {

  uint32_t m_version_;

  encryption_mode m_encryption_mode_;

  symmetric_cipher m_symm_cipher_;
  asymmetric_cipher m_asymm_cipher_;

  message_digest_algorithm m_digest_algorithm_;

  buffer_t *m_encrypted_key_;
  buffer_t *m_iv_;
  buffer_t *m_tag_;
  buffer_t *m_aad_;
  buffer_t *m_ciphertext_;
  buffer_t *m_digest_;
};

typedef struct CiphertextBlob ciphertext_blob_t;

#define GLUE(prefix, name) prefix##name
#define API(name) GLUE(CiphertextBlob_, name)

ciphertext_blob_t *API(new)(crypto_config_t cfg, size_t iv_len, size_t tag_len,
                            size_t aad_len, size_t ciphertext_len,
                            size_t digest_len) {
  ciphertext_blob_t *out = malloc(sizeof(ciphertext_blob_t));
  // set constants
  out->m_version_ = PEACEMAKR_CORE_CRYPTO_VERSION;
  out->m_encryption_mode_ = cfg.mode;
  switch (out->m_encryption_mode_) {
  case SYMMETRIC:
    out->m_encrypted_key_ = NULL;
    out->m_symm_cipher_ = cfg.symm_cipher;
    break;
  case ASYMMETRIC:
    out->m_encrypted_key_ =
        Buffer_new((size_t)EVP_CIPHER_key_length(parse_cipher(cfg)));
    out->m_asymm_cipher_ = cfg.asymm_cipher;
    out->m_symm_cipher_ = cfg.symm_cipher;
    break;
  }
  out->m_digest_algorithm_ = cfg.digest_algorithm;

  // now alloc space for buffers if we know how big they should be
  out->m_iv_ = Buffer_new(iv_len);
  out->m_tag_ = Buffer_new(tag_len);
  out->m_aad_ = Buffer_new(aad_len);
  out->m_ciphertext_ = Buffer_new(ciphertext_len);
  out->m_digest_ = Buffer_new(digest_len);

  return out;
}

void API(free)(ciphertext_blob_t *ciphertext) {
  if (ciphertext == NULL) {
    PEACEMAKR_ERROR("invalid argument passed");
    return;
  }

  Buffer_free(ciphertext->m_iv_);
  Buffer_free(ciphertext->m_tag_);
  Buffer_free(ciphertext->m_aad_);
  Buffer_free(ciphertext->m_ciphertext_);
  Buffer_free(ciphertext->m_digest_);
  free(ciphertext);
  ciphertext = NULL;
}

void API(init_iv)(ciphertext_blob_t *ciphertext, random_device_t *rng) {
  Buffer_init_rand(ciphertext->m_iv_, rng);
}

const buffer_t *API(get_iv)(ciphertext_blob_t *ciphertext) {
  return ciphertext->m_iv_;
}

buffer_t *API(mutable_encrypted_key)(ciphertext_blob_t *ciphertext) {
  return ciphertext->m_encrypted_key_;
}

buffer_t *API(mutable_tag)(ciphertext_blob_t *ciphertext) {
  return ciphertext->m_tag_;
}

buffer_t *API(mutable_aad)(ciphertext_blob_t *ciphertext) {
  return ciphertext->m_aad_;
}

buffer_t *API(mutable_ciphertext)(ciphertext_blob_t *ciphertext) {
  return ciphertext->m_ciphertext_;
}

buffer_t *API(mutable_digest)(ciphertext_blob_t *ciphertext) {
  return ciphertext->m_digest_;
}
