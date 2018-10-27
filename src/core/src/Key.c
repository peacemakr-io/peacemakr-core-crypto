//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include <Buffer.h>
#include <EVPHelper.h>
#include <Logging.h>
#include <crypto.h>
#include <random.h>

#include <stdbool.h>
#include <stdlib.h>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

static bool keygen_inner(int key_type, EVP_PKEY **pkey, int rsa_bits) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(key_type, NULL);
  EXPECT_NOT_NULL_RET_VALUE(ctx, false, "EVP_PKEY_CTX_new_id failed\n");

  int rc = EVP_PKEY_keygen_init(ctx);
  if (rc <= 0) {
    PEACEMAKR_LOG("EVP_PKEY_keygen_init failed with rc %d\n", rc);
    EVP_PKEY_CTX_free(ctx);
    return false;
  }

  if (key_type == EVP_PKEY_RSA && rsa_bits > 0 &&
      (rsa_bits == 2048 || rsa_bits == 4096)) {
    rc = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, rsa_bits);
    if (rc <= 0) {
      PEACEMAKR_LOG("set_rsa_keygen_bits failed\n");
      EVP_PKEY_CTX_free(ctx);
      return false;
    }
  }

  rc = EVP_PKEY_keygen(ctx, pkey);
  if (rc <= 0) {
    PEACEMAKR_LOG("EVP_PKEY_keygen failed\n");
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

#define GLUE(prefix, name) prefix##name
#define API(name) GLUE(PeacemakrKey_, name)

peacemakr_key_t *API(new)(crypto_config_t cfg, random_device_t *rand) {
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
      PEACEMAKR_LOG("asymmetric cipher not specified for asymmetric mode\n");
      API(free)(out);
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
        PEACEMAKR_LOG("keygen failed\n");
        API(free)(out);
        return NULL;
      }
      break;
    }
    case RSA_4096: {
      if (keygen_inner(EVP_PKEY_RSA, &out->m_contents_.asymm, 4096) == false) {
        PEACEMAKR_LOG("keygen failed\n");
        API(free)(out);
        return NULL;
      }
      break;
    }
    }
    return out;
  }
  }

  PEACEMAKR_LOG("unknown failure\n");
  API(free)(out);
  return NULL;
}

peacemakr_key_t *API(new_bytes)(crypto_config_t cfg, const uint8_t *buf,
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

peacemakr_key_t *API(new_from_master)(crypto_config_t cfg,
                                      const peacemakr_key_t *master_key,
                                      const uint8_t *key_id,
                                      const size_t key_id_len) {
  EXPECT_TRUE_RET((cfg.mode == SYMMETRIC),
                  "Can't set a raw bytes for asymmetric crypto\n");
  EXPECT_TRUE_RET((cfg.symm_cipher == AES_256_GCM || cfg.symm_cipher == CHACHA20_POLY1305),
                  "Only support generating keys for AES-256\n");
  EXPECT_NOT_NULL_RET(master_key, "Master key was NULL\n");
  EXPECT_TRUE_RET(
      (master_key->m_cfg_.mode == SYMMETRIC),
      "We use a symmetric master key to generate symmetric child keys\n");
  const buffer_t *master_key_buf = master_key->m_contents_.symm;
  size_t master_keylen = Buffer_get_size(master_key_buf);
  EXPECT_TRUE_RET((master_keylen <= INT_MAX),
                  "Length of passed master key is greater than INT_MAX\n");
  EXPECT_TRUE_RET((key_id != NULL && key_id_len > 0),
                  "key_id is null or its length was 0\n");

  const EVP_CIPHER *cipher = parse_cipher(cfg.symm_cipher);
  size_t keylen = (size_t)EVP_CIPHER_key_length(cipher);

  peacemakr_key_t *out = malloc(sizeof(peacemakr_key_t));
  out->m_cfg_ = cfg;
  out->m_contents_.symm = NULL;

  out->m_contents_.symm = Buffer_new(keylen);
  // Generate the key
  uint8_t *tmp_result = alloca(keylen);
  // Use HMAC SHA256 to generate the key using the master key and the key id
  const uint8_t *master_key_bytes = Buffer_get_bytes(master_key_buf, NULL);
  HMAC(EVP_sha256(), master_key_bytes, (int)master_keylen, key_id, key_id_len,
       tmp_result, NULL);

  Buffer_set_bytes(out->m_contents_.symm, tmp_result, keylen);

  return out;
}

peacemakr_key_t *API(new_pem_pub)(crypto_config_t cfg, const char *buf,
                                  const size_t buflen) {

  EXPECT_TRUE_RET((buf != NULL && buflen > 0),
                  "buf was null or buflen was 0\n");
  EXPECT_TRUE_RET((buflen <= INT_MAX),
                  "Length of passed master key is greater than INT_MAX\n");
  EXPECT_TRUE_RET((cfg.mode == ASYMMETRIC),
                  "Can't set a new EVP_PKEY for symmetric crypto\n");

  peacemakr_key_t *out = malloc(sizeof(peacemakr_key_t));
  out->m_cfg_ = cfg;
  out->m_contents_.asymm = NULL;

  BIO *bo = BIO_new_mem_buf(buf, (int)buflen);

  out->m_contents_.asymm = PEM_read_bio_PUBKEY(bo, NULL, NULL, NULL);
  EXPECT_NOT_NULL_CLEANUP_RET(out->m_contents_.asymm,
                              {
                                BIO_free(bo);
                                API(free)(out);
                              },
                              "PEM_read_bio_PUBKEY failed\n");

  BIO_free(bo);

  return out;
}

peacemakr_key_t *API(new_pem_priv)(crypto_config_t cfg, const char *buf,
                                   const size_t buflen) {

  EXPECT_TRUE_RET((buf != NULL && buflen != 0),
                  "buf was null or buflen was 0\n");
  EXPECT_TRUE_RET((buflen <= INT_MAX),
                  "Length of passed master key is greater than INT_MAX\n");
  EXPECT_TRUE_RET((cfg.mode == ASYMMETRIC),
                  "Can't set a new EVP_PKEY for symmetric crypto\n");

  peacemakr_key_t *out = malloc(sizeof(peacemakr_key_t));
  out->m_cfg_ = cfg;
  out->m_contents_.asymm = NULL;

  BIO *bo = BIO_new_mem_buf(buf, (int)buflen);

  out->m_contents_.asymm = PEM_read_bio_PrivateKey(bo, NULL, NULL, NULL);
  EXPECT_NOT_NULL_CLEANUP_RET(out->m_contents_.asymm,
                              {
                                BIO_free(bo);
                                API(free)(out);
                              },
                              "PEM_read_bio_PrivateKey failed\n");

  BIO_free(bo);

  return out;
}

void API(free)(peacemakr_key_t *key) {
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

crypto_config_t API(get_config)(const peacemakr_key_t *key) {
  return key->m_cfg_;
}

const buffer_t *API(symmetric)(const peacemakr_key_t *key) {
  EXPECT_TRUE_RET(
      (key->m_cfg_.mode == SYMMETRIC),
      "Attempting to access the symmetric part of an asymmetric key\n");

  return key->m_contents_.symm;
}

EVP_PKEY *API(asymmetric)(const peacemakr_key_t *key) {
  EXPECT_TRUE_RET(
      (key->m_cfg_.mode == ASYMMETRIC),
      "Attempting to access the symmetric part of an asymmetric key\n");

  return key->m_contents_.asymm;
}