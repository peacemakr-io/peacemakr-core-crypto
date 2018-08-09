//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include <Buffer.h>
#include <Logging.h>

#include <crypto.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct CiphertextBlob {

  uint32_t m_version_;

  encryption_mode m_encryption_mode_;

  union {
    symmetric_cipher symm;
    asymmetric_cipher asymm;
  } m_cipher_;

  message_digest_algorithm m_digest_algorithm_;

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
    out->m_cipher_.symm = cfg.cipher.symm;
    break;
  case ASYMMETRIC:
    out->m_cipher_.asymm = cfg.cipher.asymm;
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
