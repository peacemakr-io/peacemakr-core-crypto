//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include <Buffer.h>
#include <Logging.h>

#include "CiphertextBlob.h"
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
  EXPECT_NOT_NULL_RET(out, "malloc returned nullptr\n");
  // set constants
  out->m_version_ = PEACEMAKR_CORE_CRYPTO_VERSION;
  out->m_encryption_mode_ = cfg.mode;
  switch (out->m_encryption_mode_) {
  case SYMMETRIC:
    out->m_encrypted_key_ = NULL;
    out->m_symm_cipher_ = cfg.symm_cipher;
    break;
  case ASYMMETRIC:
    switch (cfg.asymm_cipher) {
    case NONE:
      break;
      //      case EC25519: out->m_encrypted_key_ = Buffer_new(1024); break;
    case RSA_2048:
      out->m_encrypted_key_ = Buffer_new(256);
      EXPECT_NOT_NULL_RET(out->m_encrypted_key_,
                          "creation of encrypted key buffer failed\n");
      break;
    case RSA_4096:
      out->m_encrypted_key_ = Buffer_new(512);
      EXPECT_NOT_NULL_RET(out->m_encrypted_key_,
                          "creation of encrypted key buffer failed\n");
      break;
    }
    out->m_asymm_cipher_ = cfg.asymm_cipher;
    out->m_symm_cipher_ = cfg.symm_cipher;
    break;
  }
  out->m_digest_algorithm_ = cfg.digest_algorithm;

  // now alloc space for buffers if we know how big they should be
  out->m_iv_ = Buffer_new(iv_len);
  EXPECT_TRUE_RET((out->m_iv_ != NULL || iv_len == 0),
                  "creation of iv buffer failed\n");
  out->m_tag_ = Buffer_new(tag_len);
  EXPECT_TRUE_RET((out->m_tag_ != NULL || tag_len == 0),
                  "creation of tag buffer failed\n");
  out->m_aad_ = Buffer_new(aad_len);
  EXPECT_TRUE_RET((out->m_aad_ != NULL || aad_len == 0),
                  "creation of aad buffer failed\n");
  out->m_ciphertext_ = Buffer_new(ciphertext_len);
  EXPECT_NOT_NULL_RET(out->m_ciphertext_,
                      "creation of ciphertext buffer failed\n");
  out->m_digest_ = Buffer_new(digest_len);
  EXPECT_NOT_NULL_RET(out->m_digest_, "creation of digest buffer failed\n");

  return out;
}

void API(free)(ciphertext_blob_t *ciphertext) {
  EXPECT_NOT_NULL_RET_NONE(ciphertext, "ciphertext was NULL\n");

  Buffer_free(ciphertext->m_iv_);
  Buffer_free(ciphertext->m_tag_);
  Buffer_free(ciphertext->m_aad_);
  Buffer_free(ciphertext->m_ciphertext_);
  Buffer_free(ciphertext->m_digest_);
  free(ciphertext);
  ciphertext = NULL;
}

void API(set_version)(ciphertext_blob_t *ciphertext, uint32_t version) {
  EXPECT_NOT_NULL_RET_NONE(ciphertext, "ciphertext was NULL\n");
  ciphertext->m_version_ = version;
}

const uint32_t API(version)(const ciphertext_blob_t *ciphertext) {
  EXPECT_NOT_NULL_RET_VALUE(ciphertext, 0, "ciphertext was NULL\n");
  return ciphertext->m_version_;
}

void API(init_iv)(ciphertext_blob_t *ciphertext, random_device_t *rng) {
  EXPECT_NOT_NULL_RET_NONE(ciphertext, "ciphertext was NULL\n");
  Buffer_init_rand(ciphertext->m_iv_, rng);
}

const buffer_t *API(iv)(const ciphertext_blob_t *ciphertext) {
  EXPECT_NOT_NULL_RET(ciphertext, "ciphertext was NULL\n");
  return ciphertext->m_iv_;
}

void API(set_iv)(ciphertext_blob_t *ciphertext, const unsigned char *iv,
                 size_t ivlen) {
  EXPECT_NOT_NULL_RET_NONE(ciphertext, "ciphertext was NULL\n");
  EXPECT_NOT_NULL_RET_NONE(ciphertext->m_iv_,
                           "iv buffer for this ciphertext was NULL\n");
  EXPECT_NOT_NULL_RET_NONE(iv, "ciphertext was NULL\n");
  EXPECT_TRUE_RET_NONE((ivlen != 0), "ivlen was 0\n");
  Buffer_set_bytes(ciphertext->m_iv_, iv, ivlen);
}

buffer_t *API(mutable_encrypted_key)(ciphertext_blob_t *ciphertext) {
  EXPECT_NOT_NULL_RET(ciphertext, "ciphertext was NULL\n");
  return ciphertext->m_encrypted_key_;
}

const buffer_t *API(encrypted_key)(const ciphertext_blob_t *ciphertext) {
  EXPECT_NOT_NULL_RET(ciphertext, "ciphertext was NULL\n");
  return ciphertext->m_encrypted_key_;
}

buffer_t *API(mutable_tag)(ciphertext_blob_t *ciphertext) {
  EXPECT_NOT_NULL_RET(ciphertext, "ciphertext was NULL\n");
  return ciphertext->m_tag_;
}

const buffer_t *API(tag)(const ciphertext_blob_t *ciphertext) {
  EXPECT_NOT_NULL_RET(ciphertext, "ciphertext was NULL\n");
  return ciphertext->m_tag_;
}

buffer_t *API(mutable_aad)(ciphertext_blob_t *ciphertext) {
  EXPECT_NOT_NULL_RET(ciphertext, "ciphertext was NULL\n");
  return ciphertext->m_aad_;
}

const buffer_t *API(aad)(const ciphertext_blob_t *ciphertext) {
  EXPECT_NOT_NULL_RET(ciphertext, "ciphertext was NULL\n");
  return ciphertext->m_aad_;
}

buffer_t *API(mutable_ciphertext)(ciphertext_blob_t *ciphertext) {
  EXPECT_NOT_NULL_RET(ciphertext, "ciphertext was NULL\n");
  return ciphertext->m_ciphertext_;
}

const buffer_t *API(ciphertext)(const ciphertext_blob_t *ciphertext) {
  EXPECT_NOT_NULL_RET(ciphertext, "ciphertext was NULL\n");
  return ciphertext->m_ciphertext_;
}

buffer_t *API(mutable_digest)(ciphertext_blob_t *ciphertext) {
  EXPECT_NOT_NULL_RET(ciphertext, "ciphertext was NULL\n");
  return ciphertext->m_digest_;
}

const symmetric_cipher API(symm_cipher)(const ciphertext_blob_t *ciphertext) {
  return ciphertext->m_symm_cipher_;
}

const asymmetric_cipher API(asymm_cipher)(const ciphertext_blob_t *ciphertext) {
  return ciphertext->m_asymm_cipher_;
}

const message_digest_algorithm
API(digest_algo)(const ciphertext_blob_t *ciphertext) {
  return ciphertext->m_digest_algorithm_;
}

const encryption_mode
API(encryption_mode)(const ciphertext_blob_t *ciphertext) {
  return ciphertext->m_encryption_mode_;
}
