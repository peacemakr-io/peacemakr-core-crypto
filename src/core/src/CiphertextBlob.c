//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include "Buffer.h"
#include "Logging.h"
#include "crypto.h"

#include "CiphertextBlob.h"
#include "EVPHelper.h"

#include <string.h>

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
  buffer_t *m_signature_;
};

typedef struct CiphertextBlob ciphertext_blob_t;

ciphertext_blob_t *
ciphertext_blob_new(const crypto_config_t cfg, const size_t iv_len,
                    const size_t tag_len, const size_t aad_len,
                    const size_t ciphertext_len, const size_t digest_len) {
  ciphertext_blob_t *out = malloc(sizeof(ciphertext_blob_t));
  EXPECT_NOT_NULL_RET(out, "malloc returned nullptr\n")

  out->m_encrypted_key_ = NULL;
  out->m_iv_ = NULL;
  out->m_tag_ = NULL;
  out->m_aad_ = NULL;
  out->m_ciphertext_ = NULL;
  out->m_signature_ = NULL;

  // set constants
  out->m_version_ = PEACEMAKR_CORE_CRYPTO_VERSION;
  out->m_encrypted_key_ = NULL;
  out->m_encryption_mode_ = cfg.mode;
  out->m_symm_cipher_ = cfg.symm_cipher;
  out->m_asymm_cipher_ = cfg.asymm_cipher;
  out->m_digest_algorithm_ = cfg.digest_algorithm;
  switch (out->m_encryption_mode_) {
  case SYMMETRIC:
    break;
  case ASYMMETRIC:
    switch (cfg.asymm_cipher) {
    case ASYMMETRIC_UNSPECIFIED:
      break;
    case RSA_2048:
      out->m_encrypted_key_ = buffer_new(256);
      EXPECT_NOT_NULL_CLEANUP_RET(out->m_encrypted_key_,
                                  ciphertext_blob_free(out),
                                  "creation of encrypted key buffer failed\n")
      break;
    case RSA_4096:
      out->m_encrypted_key_ = buffer_new(512);
      EXPECT_NOT_NULL_CLEANUP_RET(out->m_encrypted_key_,
                                  ciphertext_blob_free(out),
                                  "creation of encrypted key buffer failed\n")
      break;
    default:
      break;
    }
    break;
  }

  // now alloc space for buffers if we know how big they should be
  out->m_iv_ = buffer_new(iv_len);
  EXPECT_TRUE_CLEANUP_RET((out->m_iv_ != NULL || iv_len == 0),
                          ciphertext_blob_free(out),
                          "creation of iv buffer failed\n")
  out->m_tag_ = buffer_new(tag_len);
  EXPECT_TRUE_CLEANUP_RET((out->m_tag_ != NULL || tag_len == 0),
                          ciphertext_blob_free(out),
                          "creation of tag buffer failed\n")
  out->m_aad_ = buffer_new(aad_len);
  EXPECT_TRUE_CLEANUP_RET((out->m_aad_ != NULL || aad_len == 0),
                          ciphertext_blob_free(out),
                          "creation of aad buffer failed\n")
  out->m_ciphertext_ = buffer_new(ciphertext_len);
  EXPECT_TRUE_CLEANUP_RET((out->m_ciphertext_ != NULL || ciphertext_len == 0),
                          ciphertext_blob_free(out),
                          "creation of ciphertext buffer failed\n")
  out->m_signature_ = buffer_new(digest_len);
  EXPECT_TRUE_CLEANUP_RET((out->m_signature_ != NULL || digest_len == 0),
                          ciphertext_blob_free(out),
                          "creation of digest buffer failed\n")

  return out;
}

ciphertext_blob_t *
ciphertext_blob_from_buffers(const crypto_config_t cfg, buffer_t *encrypted_key,
                             buffer_t *iv, buffer_t *tag, buffer_t *aad,
                             buffer_t *ciphertext, buffer_t *signature) {
  ciphertext_blob_t *out = malloc(sizeof(ciphertext_blob_t));
  EXPECT_NOT_NULL_RET(out, "malloc returned nullptr\n")
  // set constants
  out->m_version_ = PEACEMAKR_CORE_CRYPTO_VERSION;
  out->m_encrypted_key_ = NULL;
  out->m_encryption_mode_ = cfg.mode;
  out->m_symm_cipher_ = cfg.symm_cipher;
  out->m_asymm_cipher_ = cfg.asymm_cipher;
  out->m_digest_algorithm_ = cfg.digest_algorithm;

  if (buffer_get_size(encrypted_key) != 0) {
    out->m_encrypted_key_ = encrypted_key;
  } else {
    out->m_encrypted_key_ = NULL;
  }

  out->m_iv_ = iv;
  out->m_tag_ = tag;
  out->m_aad_ = aad;
  out->m_ciphertext_ = ciphertext;
  out->m_signature_ = signature;

  return out;
}

void ciphertext_blob_free(ciphertext_blob_t *ciphertext) {
  EXPECT_NOT_NULL_RET_NONE(ciphertext, "ciphertext was NULL\n")

  buffer_free(ciphertext->m_encrypted_key_);
  buffer_free(ciphertext->m_iv_);
  buffer_free(ciphertext->m_tag_);
  buffer_free(ciphertext->m_aad_);
  buffer_free(ciphertext->m_ciphertext_);
  buffer_free(ciphertext->m_signature_);
  free(ciphertext);
  ciphertext = NULL;
}

void ciphertext_blob_set_version(ciphertext_blob_t *ciphertext,
                                 uint32_t version) {
  EXPECT_NOT_NULL_RET_NONE(ciphertext, "ciphertext was NULL\n")
  ciphertext->m_version_ = version;
}

const uint32_t ciphertext_blob_version(const ciphertext_blob_t *ciphertext) {
  EXPECT_NOT_NULL_RET_VALUE(ciphertext, 0, "ciphertext was NULL\n")
  return ciphertext->m_version_;
}

void ciphertext_blob_init_iv(ciphertext_blob_t *ciphertext,
                             random_device_t *rng) {
  EXPECT_NOT_NULL_RET_NONE(ciphertext, "ciphertext was NULL\n")
  buffer_init_rand(ciphertext->m_iv_, rng);
}

const buffer_t *ciphertext_blob_iv(const ciphertext_blob_t *ciphertext) {
  EXPECT_NOT_NULL_RET(ciphertext, "ciphertext was NULL\n")
  return ciphertext->m_iv_;
}

void ciphertext_blob_set_iv(ciphertext_blob_t *ciphertext,
                            const unsigned char *iv, size_t ivlen) {
  EXPECT_NOT_NULL_RET_NONE(ciphertext, "ciphertext was NULL\n")
  EXPECT_NOT_NULL_RET_NONE(ciphertext->m_iv_,
                           "iv buffer for this ciphertext was NULL\n")
  EXPECT_NOT_NULL_RET_NONE(iv, "ciphertext was NULL\n")
  EXPECT_TRUE_RET_NONE((ivlen != 0), "ivlen was 0\n")
  buffer_set_bytes(ciphertext->m_iv_, iv, ivlen);
}

buffer_t *ciphertext_blob_mutable_encrypted_key(ciphertext_blob_t *ciphertext) {
  EXPECT_NOT_NULL_RET(ciphertext, "ciphertext was NULL\n")
  return ciphertext->m_encrypted_key_;
}

const buffer_t *
ciphertext_blob_encrypted_key(const ciphertext_blob_t *ciphertext) {
  EXPECT_NOT_NULL_RET(ciphertext, "ciphertext was NULL\n")
  return ciphertext->m_encrypted_key_;
}

buffer_t *ciphertext_blob_mutable_tag(ciphertext_blob_t *ciphertext) {
  EXPECT_NOT_NULL_RET(ciphertext, "ciphertext was NULL\n")
  return ciphertext->m_tag_;
}

const buffer_t *ciphertext_blob_tag(const ciphertext_blob_t *ciphertext) {
  EXPECT_NOT_NULL_RET(ciphertext, "ciphertext was NULL\n")
  return ciphertext->m_tag_;
}

buffer_t *ciphertext_blob_mutable_aad(ciphertext_blob_t *ciphertext) {
  EXPECT_NOT_NULL_RET(ciphertext, "ciphertext was NULL\n")
  return ciphertext->m_aad_;
}

const buffer_t *ciphertext_blob_aad(const ciphertext_blob_t *ciphertext) {
  EXPECT_NOT_NULL_RET(ciphertext, "ciphertext was NULL\n")
  return ciphertext->m_aad_;
}

buffer_t *ciphertext_blob_mutable_ciphertext(ciphertext_blob_t *ciphertext) {
  EXPECT_NOT_NULL_RET(ciphertext, "ciphertext was NULL\n")
  return ciphertext->m_ciphertext_;
}

const buffer_t *
ciphertext_blob_ciphertext(const ciphertext_blob_t *ciphertext) {
  EXPECT_NOT_NULL_RET(ciphertext, "ciphertext was NULL\n")
  return ciphertext->m_ciphertext_;
}

buffer_t *ciphertext_blob_mutable_signature(ciphertext_blob_t *ciphertext) {
  EXPECT_NOT_NULL_RET(ciphertext, "ciphertext was NULL\n")
  return ciphertext->m_signature_;
}

const buffer_t *ciphertext_blob_signature(const ciphertext_blob_t *ciphertext) {
  EXPECT_NOT_NULL_RET(ciphertext, "ciphertext was NULL\n")
  return ciphertext->m_signature_;
}

const symmetric_cipher
ciphertext_blob_symm_cipher(const ciphertext_blob_t *ciphertext) {
  return ciphertext->m_symm_cipher_;
}

const asymmetric_cipher
ciphertext_blob_asymm_cipher(const ciphertext_blob_t *ciphertext) {
  return ciphertext->m_asymm_cipher_;
}

const message_digest_algorithm
ciphertext_blob_digest_algo(const ciphertext_blob_t *ciphertext) {
  return ciphertext->m_digest_algorithm_;
}

const encryption_mode
ciphertext_blob_encryption_mode(const ciphertext_blob_t *ciphertext) {
  return ciphertext->m_encryption_mode_;
}

bool ciphertext_blob_compare(const ciphertext_blob_t *lhs,
                             const ciphertext_blob_t *rhs) {
  bool equal = true;

  if (lhs->m_version_ != rhs->m_version_) {
    PEACEMAKR_LOG("Versions not equal\n");
    equal = false;
  }

  if (lhs->m_encryption_mode_ != rhs->m_encryption_mode_) {
    PEACEMAKR_LOG("Encryption Modes not equal\n");
    equal = false;
  }

  if (lhs->m_symm_cipher_ != rhs->m_symm_cipher_) {
    PEACEMAKR_LOG("symm_cipher not equal\n");
    equal = false;
  }

  if (lhs->m_asymm_cipher_ != rhs->m_asymm_cipher_) {
    PEACEMAKR_LOG("asymm_cipher not equal\n");
    equal = false;
  }

  if (lhs->m_digest_algorithm_ != rhs->m_digest_algorithm_) {
    PEACEMAKR_LOG("digest_algorithm not equal\n");
    equal = false;
  }

  if (lhs->m_encrypted_key_ != NULL && rhs->m_encrypted_key_ != NULL) {
    size_t lhs_size = 0, rhs_size = 1;
    const uint8_t *lhs_buf = buffer_get_bytes(lhs->m_encrypted_key_, &lhs_size);
    const uint8_t *rhs_buf = buffer_get_bytes(rhs->m_encrypted_key_, &rhs_size);
    if (lhs_size != rhs_size) {
      PEACEMAKR_LOG("encrypted_key lengths not equal\n");
      equal = false;
    } else if (0 != memcmp(lhs_buf, rhs_buf, lhs_size)) {
      PEACEMAKR_LOG("encrypted_key buffers not equal\n");
      for (int i = 0; i < lhs_size; ++i) {
        printf("%d: %x - %x\n", i, lhs_buf[i], rhs_buf[i]);
      }
      equal = false;
    }
  }

  if (lhs->m_iv_ != NULL && rhs->m_iv_ != NULL) {
    size_t lhs_size = 0, rhs_size = 1;
    const uint8_t *lhs_buf = buffer_get_bytes(lhs->m_iv_, &lhs_size);
    const uint8_t *rhs_buf = buffer_get_bytes(rhs->m_iv_, &rhs_size);
    if (lhs_size != rhs_size) {
      PEACEMAKR_LOG("iv lengths not equal\n");
      equal = false;
    } else if (0 != memcmp(lhs_buf, rhs_buf, lhs_size)) {
      PEACEMAKR_LOG("iv buffers not equal\n");
      //      for (int i = 0; i < lhs_size; ++i) {
      //        printf("%d: %x - %x\n", i, lhs_buf[i], rhs_buf[i]);
      //      }
      equal = false;
    }
  }

  if (lhs->m_tag_ != NULL && rhs->m_tag_ != NULL) {
    size_t lhs_size = 0, rhs_size = 1;
    const uint8_t *lhs_buf = buffer_get_bytes(lhs->m_tag_, &lhs_size);
    const uint8_t *rhs_buf = buffer_get_bytes(rhs->m_tag_, &rhs_size);
    if (lhs_size != rhs_size) {
      PEACEMAKR_LOG("tag lengths not equal\n");
      equal = false;
    } else if (0 != memcmp(lhs_buf, rhs_buf, lhs_size)) {
      PEACEMAKR_LOG("tag buffers not equal\n");
      //      for (int i = 0; i < lhs_size; ++i) {
      //        printf("%d: %x - %x\n", i, lhs_buf[i], rhs_buf[i]);
      //      }
      equal = false;
    }
  }

  if (lhs->m_aad_ != NULL && rhs->m_aad_ != NULL) {
    size_t lhs_size = 0, rhs_size = 1;
    const uint8_t *lhs_buf = buffer_get_bytes(lhs->m_aad_, &lhs_size);
    const uint8_t *rhs_buf = buffer_get_bytes(rhs->m_aad_, &rhs_size);
    if (lhs_size != rhs_size) {
      PEACEMAKR_LOG("aad lengths not equal\n");
      equal = false;
    } else if (0 != memcmp(lhs_buf, rhs_buf, lhs_size)) {
      PEACEMAKR_LOG("aad buffers not equal\n");
      //      for (int i = 0; i < lhs_size; ++i) {
      //        printf("%d: %x - %x\n", i, lhs_buf[i], rhs_buf[i]);
      //      }
      equal = false;
    }
  }

  if (lhs->m_ciphertext_ != NULL && rhs->m_ciphertext_ != NULL) {
    size_t lhs_size = 0, rhs_size = 1;
    const uint8_t *lhs_buf = buffer_get_bytes(lhs->m_ciphertext_, &lhs_size);
    const uint8_t *rhs_buf = buffer_get_bytes(rhs->m_ciphertext_, &rhs_size);
    if (lhs_size != rhs_size) {
      PEACEMAKR_LOG("ciphertext lengths not equal\n");
      equal = false;
    } else if (0 != memcmp(lhs_buf, rhs_buf, lhs_size)) {
      PEACEMAKR_LOG("ciphertext buffers not equal\n");
      //      for (int i = 0; i < lhs_size; ++i) {
      //        printf("%d: %x - %x\n", i, lhs_buf[i], rhs_buf[i]);
      //      }
      equal = false;
    }
  }

  if (lhs->m_signature_ != NULL && rhs->m_signature_ != NULL) {
    size_t lhs_size = 0, rhs_size = 1;
    const uint8_t *lhs_buf = buffer_get_bytes(lhs->m_signature_, &lhs_size);
    const uint8_t *rhs_buf = buffer_get_bytes(rhs->m_signature_, &rhs_size);
    if (lhs_size != rhs_size) {
      PEACEMAKR_LOG("digest lengths not equal\n");
      equal = false;
    } else if (0 != memcmp(lhs_buf, rhs_buf, lhs_size)) {
      PEACEMAKR_LOG("digest buffers not equal\n");
      //      for (int i = 0; i < lhs_size; ++i) {
      //        printf("%d: %x - %x\n", i, lhs_buf[i], rhs_buf[i]);
      //      }
      equal = false;
    }
  }

  return equal;
}
