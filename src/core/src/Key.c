//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include "Buffer.h"
#include "EVPHelper.h"
#include "Logging.h"

#include <memory.h>

#include <openssl/pem.h>
#include <openssl/rsa.h>

static bool keygen_inner(int key_type, EVP_PKEY **pkey, int rsa_bits) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(key_type, NULL);
  EXPECT_NOT_NULL_RET_VALUE(ctx, false, "EVP_PKEY_CTX_new_id failed\n");

  int rc = EVP_PKEY_keygen_init(ctx);
  if (rc <= 0) {
    PEACEMAKR_ERROR("EVP_PKEY_keygen_init failed with rc %d\n", rc);
    EVP_PKEY_CTX_free(ctx);
    return false;
  }

  if (key_type == EVP_PKEY_RSA && rsa_bits > 0 &&
      (rsa_bits == 2048 || rsa_bits == 4096)) {
    rc = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, rsa_bits);
    if (rc <= 0) {
      PEACEMAKR_ERROR("set_rsa_keygen_bits failed\n");
      EVP_PKEY_CTX_free(ctx);
      return false;
    }
  }

  rc = EVP_PKEY_keygen(ctx, pkey);
  if (rc <= 0) {
    PEACEMAKR_ERROR("EVP_PKEY_keygen failed\n");
    EVP_PKEY_CTX_free(ctx);
    return false;
  }

  EVP_PKEY_CTX_free(ctx);
  return true;
}

struct PeacemakrKey {
  crypto_config_t m_cfg_;
  union {
    buffer_t *symm;
    EVP_PKEY *asymm;
  } m_contents_;
};

typedef struct PeacemakrKey peacemakr_key_t;

peacemakr_key_t *PeacemakrKey_new(crypto_config_t cfg, random_device_t *rand) {
  EXPECT_NOT_NULL_RET(
      rand, "Cannot create a new key without a source of randomness\n");

  peacemakr_key_t *out = malloc(sizeof(peacemakr_key_t));
  out->m_cfg_ = cfg;

  switch (cfg.mode) {
  case SYMMETRIC: {
    out->m_contents_.symm = NULL;
    const EVP_CIPHER *cipher = parse_cipher(cfg.symm_cipher);
    size_t keylen = (size_t)EVP_CIPHER_key_length(cipher);

    out->m_contents_.symm = Buffer_new(keylen);
    Buffer_init_rand(out->m_contents_.symm, rand);
    return out;
  }
  case ASYMMETRIC: {
    out->m_contents_.asymm = NULL;
    switch (cfg.asymm_cipher) {
    case NONE: {
      PEACEMAKR_ERROR("asymmetric cipher not specified for asymmetric mode\n");
      PeacemakrKey_free(out);
      return NULL;
    }
      //    case EC25519: {
      //      if (keygen_inner(NID_X25519, &out->m_evp_pkey_, 0) == false) {
      //        PEACEMAKR_LOG("keygen failed\n");
      //        return NULL;
      //      }
      //      break;
      //    }
    case RSA_2048: {
      if (keygen_inner(EVP_PKEY_RSA, &out->m_contents_.asymm, 2048) == false) {
        PEACEMAKR_ERROR("keygen failed\n");
        PeacemakrKey_free(out);
        return NULL;
      }
      break;
    }
    case RSA_4096: {
      if (keygen_inner(EVP_PKEY_RSA, &out->m_contents_.asymm, 4096) == false) {
        PEACEMAKR_ERROR("keygen failed\n");
        PeacemakrKey_free(out);
        return NULL;
      }
      break;
    }
    }
    return out;
  }
  }

  PEACEMAKR_ERROR("unknown failure\n");
  PeacemakrKey_free(out);
  return NULL;
}

peacemakr_key_t *PeacemakrKey_new_bytes(crypto_config_t cfg, const uint8_t *buf,
                                        const size_t bufsize) {
  EXPECT_TRUE_RET((cfg.mode == SYMMETRIC),
                  "Can't set a raw bytes for asymmetric crypto\n");
  EXPECT_NOT_NULL_RET(buf, "buffer is null\n");

  const EVP_CIPHER *cipher = parse_cipher(cfg.symm_cipher);
  size_t keylen = (size_t)EVP_CIPHER_key_length(cipher);
  EXPECT_TRUE_RET((bufsize >= keylen), "byte buffer was too small\n");

  peacemakr_key_t *out = malloc(sizeof(peacemakr_key_t));
  out->m_cfg_ = cfg;
  out->m_contents_.symm = NULL;

  out->m_contents_.symm = Buffer_new(keylen);
  Buffer_set_bytes(out->m_contents_.symm, buf, keylen);

  return out;
}

peacemakr_key_t *PeacemakrKey_new_from_master(crypto_config_t cfg,
                                              const peacemakr_key_t *master_key,
                                              const uint8_t *key_id,
                                              const size_t key_id_len) {
  EXPECT_TRUE_RET((cfg.mode == SYMMETRIC),
                  "Can't set a raw bytes for asymmetric crypto\n");

  const EVP_CIPHER *cipher = parse_cipher(cfg.symm_cipher);
  size_t keylen = (size_t)EVP_CIPHER_key_length(cipher);
  uint8_t *keybytes = NULL;
  // Compute HMAC
  switch (cfg.symm_cipher) {
  case AES_256_GCM:
  case CHACHA20_POLY1305:
    keybytes = peacemakr_hmac(SHA3_256, master_key, key_id, key_id_len, NULL);
    break;
  default:
    PEACEMAKR_ERROR("Unsupported symmetric cipher for HMAC key generation\n");
    return NULL;
  }

  peacemakr_key_t *out = PeacemakrKey_new_bytes(cfg, keybytes, keylen);
  free(keybytes);

  return out;
}

peacemakr_key_t *PeacemakrKey_new_pem(crypto_config_t cfg, const char *buf,
                                      const size_t buflen, bool is_priv) {

  EXPECT_TRUE_RET((buf != NULL && buflen > 0),
                  "buf was null or buflen was 0\n");
  EXPECT_TRUE_RET((buflen <= INT_MAX),
                  "Length of passed pem file is greater than INT_MAX\n");
  EXPECT_TRUE_RET((cfg.mode == ASYMMETRIC),
                  "Can't set a new EVP_PKEY for symmetric crypto\n");

  peacemakr_key_t *out = malloc(sizeof(peacemakr_key_t));
  out->m_cfg_ = cfg;
  out->m_contents_.asymm = NULL;

  BIO *bo = BIO_new_mem_buf(buf, (int)buflen);
  RSA *rsaKey = NULL;
  if (is_priv) {
    out->m_contents_.asymm = PEM_read_bio_PrivateKey(bo, NULL, NULL, NULL);
    EXPECT_NOT_NULL_CLEANUP_RET(out->m_contents_.asymm,
                                {
                                  BIO_free(bo);
                                  PeacemakrKey_free(out);
                                },
                                "PEM_read_bio_PrivateKey failed\n");
  } else {
    if (!PEM_read_bio_RSA_PUBKEY(bo, &rsaKey, NULL, NULL)) {
      PEACEMAKR_ERROR("PEM_read_bio_RSA_PUBKEY failed\n");
      BIO_free(bo);
      PeacemakrKey_free(out);
      RSA_free(rsaKey);
      return NULL;
    }
    out->m_contents_.asymm = EVP_PKEY_new();
    if (1 != EVP_PKEY_assign_RSA(out->m_contents_.asymm, rsaKey)) {
      PEACEMAKR_ERROR("EVP_PKEY_assign_RSA failed\n");
      BIO_free(bo);
      RSA_free(rsaKey);
      PeacemakrKey_free(out);
      return NULL;
    }
    EXPECT_NOT_NULL_CLEANUP_RET(out->m_contents_.asymm,
                                {
                                  BIO_free(bo);
                                  PeacemakrKey_free(out);
                                  RSA_free(rsaKey);
                                },
                                "PEM_read_bio_PUBKEY failed\n");
  }

  BIO_free(bo);

  return out;
}

peacemakr_key_t *PeacemakrKey_new_pem_pub(crypto_config_t cfg, const char *buf,
                                          const size_t buflen) {
  return PeacemakrKey_new_pem(cfg, buf, buflen, false);
}

peacemakr_key_t *PeacemakrKey_new_pem_priv(crypto_config_t cfg, const char *buf,
                                           const size_t buflen) {
  return PeacemakrKey_new_pem(cfg, buf, buflen, true);
}

void PeacemakrKey_free(peacemakr_key_t *key) {
  EXPECT_NOT_NULL_RET_NONE(key, "key was null\n");

  switch (key->m_cfg_.mode) {
  case SYMMETRIC: {
    Buffer_free(key->m_contents_.symm); // securely frees the memory
    break;
  }
  case ASYMMETRIC: {
    EVP_PKEY_free(key->m_contents_.asymm);
    break;
  }
  }
  free(key);
  key = NULL;
}

crypto_config_t PeacemakrKey_get_config(const peacemakr_key_t *key) {
  return key->m_cfg_;
}

const buffer_t *PeacemakrKey_symmetric(const peacemakr_key_t *key) {
  EXPECT_TRUE_RET(
      (key->m_cfg_.mode == SYMMETRIC),
      "Attempting to access the symmetric part of an asymmetric key\n");

  return key->m_contents_.symm;
}

EVP_PKEY *PeacemakrKey_asymmetric(const peacemakr_key_t *key) {
  EXPECT_TRUE_RET(
      (key->m_cfg_.mode == ASYMMETRIC),
      "Attempting to access the asymmetric part of a symmetric key\n");

  return key->m_contents_.asymm;
}

bool PeacemakrKey_priv_to_pem(const peacemakr_key_t *key, char **buf,
                              size_t *bufsize) {
  EXPECT_NOT_NULL_RET_VALUE(key, false, "Cannot serialize a NULL key\n");
  EXPECT_NOT_NULL_RET_VALUE(buf, false,
                            "Cannot serialize into a NULL buffer\n");
  EXPECT_NOT_NULL_RET_VALUE(bufsize, false,
                            "Cannot serialize into a NULL bufsize\n");

  BIO *bio = BIO_new(BIO_s_secmem());
  if (!PEM_write_bio_PrivateKey(bio, key->m_contents_.asymm, NULL, NULL, 0,
                                NULL, NULL)) {
    PEACEMAKR_OPENSSL_LOG;
    PEACEMAKR_ERROR("Failed to write the PrivateKey\n");
    return false;
  }
  if (BIO_eof(bio)) {
    PEACEMAKR_ERROR("No data stored in bio\n");
    return false;
  }
  char *memdata = NULL;
  *bufsize = BIO_get_mem_data(bio, &memdata);
  if (memdata == NULL) {
    BIO_free(bio);
    PEACEMAKR_ERROR("Failed to get memdata from bio\n");
    return false;
  }
  *buf = calloc(*bufsize, sizeof(char));
  memcpy(*buf, memdata, *bufsize);
  BIO_free(bio);
  return true;
}

bool PeacemakrKey_pub_to_pem(const peacemakr_key_t *key, char **buf,
                             size_t *bufsize) {
  EXPECT_NOT_NULL_RET_VALUE(key, false, "Cannot serialize a NULL key\n");
  EXPECT_NOT_NULL_RET_VALUE(buf, false,
                            "Cannot serialize into a NULL buffer\n");
  EXPECT_NOT_NULL_RET_VALUE(bufsize, false,
                            "Cannot serialize into a NULL bufsize\n");

  BIO *bio = BIO_new(BIO_s_mem());
  if (!PEM_write_bio_PUBKEY(bio, key->m_contents_.asymm)) {
    PEACEMAKR_OPENSSL_LOG;
    PEACEMAKR_ERROR("Failed to write the PrivateKey\n");
    return false;
  }
  if (BIO_eof(bio)) {
    PEACEMAKR_ERROR("No data stored in bio\n");
    return false;
  }
  char *memdata = NULL;
  *bufsize = BIO_get_mem_data(bio, &memdata);
  if (memdata == NULL) {
    BIO_free(bio);
    PEACEMAKR_ERROR("Failed to get memdata from bio\n");
    return false;
  }
  *buf = calloc(*bufsize, sizeof(char));
  memcpy(*buf, memdata, *bufsize);
  BIO_free(bio);
  return true;
}
