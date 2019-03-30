//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include "Key.h"
#include "Buffer.h"
#include "EVPHelper.h"
#include "Logging.h"

#include <memory.h>

#include <openssl/dh.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
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

typedef enum {
  P256,
  P384,
  P521,
} curve_t;

static bool dh_keygen_inner(EVP_PKEY **pkey, curve_t curve) {
  EVP_PKEY_CTX *pctx, *kctx;
  EVP_PKEY *params = NULL;

  /* Create the context for parameter generation */
  if (NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) {
    PEACEMAKR_OPENSSL_LOG;
    return false;
  }

  /* Initialise the parameter generation */
  if (1 != EVP_PKEY_paramgen_init(pctx)) {
    PEACEMAKR_OPENSSL_LOG;
    return false;
  }

  int rc = 0;
  switch (curve) {
  case P256: {
    rc = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    break;
  }
  case P384: {
    rc = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp384r1);
    break;
  }
  case P521: {
    rc = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp521r1);
    break;
  }
  }

  if (rc != 1) {
    PEACEMAKR_OPENSSL_LOG;
    return false;
  }

  /* Create the parameter object params */
  if (!EVP_PKEY_paramgen(pctx, &params)) {
    PEACEMAKR_OPENSSL_LOG;
    return false;
  }

  /* Create the context for the key generation */
  if (NULL == (kctx = EVP_PKEY_CTX_new(params, NULL))) {
    PEACEMAKR_OPENSSL_LOG;
    return false;
  }

  /* Generate the key */
  if (1 != EVP_PKEY_keygen_init(kctx)) {
    PEACEMAKR_OPENSSL_LOG;
    return false;
  }

  if (1 != EVP_PKEY_keygen(kctx, pkey)) {
    PEACEMAKR_OPENSSL_LOG;
    return false;
  }

  EVP_PKEY_CTX_free(pctx);
  EVP_PKEY_CTX_free(kctx);
  EVP_PKEY_free(params);
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
  EXPECT_NOT_NULL_RET(out, "Malloc failed\n");

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
    case ECDH_P256: {
      if (dh_keygen_inner(&out->m_contents_.asymm, P256) == false) {
        PEACEMAKR_ERROR("keygen failed\n");
        PeacemakrKey_free(out);
        return NULL;
      }
      break;
    }
    case ECDH_P384: {
      if (dh_keygen_inner(&out->m_contents_.asymm, P384) == false) {
        PEACEMAKR_ERROR("keygen failed\n");
        PeacemakrKey_free(out);
        return NULL;
      }
      break;
    }
    case ECDH_P521: {
      if (dh_keygen_inner(&out->m_contents_.asymm, P521) == false) {
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
                                        const size_t buf_len) {
  EXPECT_TRUE_RET((cfg.mode == SYMMETRIC),
                  "Can't set a raw bytes for asymmetric crypto\n");
  EXPECT_NOT_NULL_RET(buf, "buffer is null\n");

  const EVP_CIPHER *cipher = parse_cipher(cfg.symm_cipher);
  size_t keylen = (size_t)EVP_CIPHER_key_length(cipher);
  EXPECT_TRUE_RET((buf_len >= keylen), "byte buffer was too small\n");

  peacemakr_key_t *out = malloc(sizeof(peacemakr_key_t));
  EXPECT_NOT_NULL_RET(out, "Malloc failed!\n");

  out->m_cfg_ = cfg;
  out->m_contents_.symm = NULL;

  out->m_contents_.symm = Buffer_new(keylen);
  Buffer_set_bytes(out->m_contents_.symm, buf, keylen);

  return out;
}

peacemakr_key_t *PeacemakrKey_new_from_password(
    crypto_config_t cfg, const uint8_t *password, const size_t password_len,
    const uint8_t *salt, const size_t salt_len, const size_t iteration_count) {
  EXPECT_TRUE_RET((cfg.mode == SYMMETRIC),
                  "Can't derive an asymmetric key from a password\n");
  EXPECT_NOT_NULL_RET(password, "buffer is null\n");
  EXPECT_TRUE_RET((password_len >= 0),
                  "Password size cannot be less than or equal to zero\n");
  EXPECT_NOT_NULL_RET(salt, "Random device cannot be null\n");
  EXPECT_TRUE_RET((salt_len >= 0),
                  "Salt size cannot be less than or equal to zero\n");
  EXPECT_TRUE_RET((iteration_count >= 0),
                  "Iteration count cannot be less than or equal to zero\n");

  const EVP_CIPHER *cipher = parse_cipher(cfg.symm_cipher);
  const EVP_MD *md = parse_digest(cfg.digest_algorithm);

  const size_t keylen = EVP_CIPHER_key_length(cipher);
  uint8_t *keybuf = alloca(keylen);

  // Create the key
  if (1 != PKCS5_PBKDF2_HMAC((const char *)password, password_len, salt,
                             salt_len, iteration_count, md, keylen, keybuf)) {
    PEACEMAKR_OPENSSL_LOG;
    return NULL;
  }

  return PeacemakrKey_new_bytes(cfg, keybuf, keylen);
}

peacemakr_key_t *PeacemakrKey_new_from_master(crypto_config_t cfg,
                                              const peacemakr_key_t *master_key,
                                              const uint8_t *key_id,
                                              const size_t key_id_len) {
  EXPECT_TRUE_RET((cfg.mode == SYMMETRIC),
                  "Can't set a raw bytes for asymmetric crypto\n");

  // digest length in bytes
  size_t digestbytes = get_digest_len(cfg.digest_algorithm);
  // digestlen should be in bits
  size_t digestbits = digestbytes * 8;

  // Get the number of bits required for the key
  int keybytes_int = EVP_CIPHER_key_length(parse_cipher(cfg.symm_cipher));
  if (keybytes_int <= 0) {
    PEACEMAKR_OPENSSL_LOG;
    PEACEMAKR_ERROR("Cipher key length failed\n");
    return NULL;
  }
  uint32_t keybytes = (uint32_t)keybytes_int;
  uint32_t keybits = keybytes * 8;

  // Number of times to perform the HMAC operation
  size_t rounds = keybits / digestbits + (keybits % digestbits != 0);

  // The input to the HMAC
  size_t input_bytes_len = sizeof(uint32_t) + key_id_len + sizeof(uint32_t);
  uint8_t *input_bytes = alloca(input_bytes_len);

  // Copy over the input data and the desired key bits (NIST SP 800-108)
  memcpy(input_bytes + sizeof(uint32_t), key_id, key_id_len);
  memcpy(input_bytes + sizeof(uint32_t) + key_id_len, &keybits,
         sizeof(uint32_t));

  // Get the data out of the master key for the HMAAC
  const buffer_t *master_key_buf = PeacemakrKey_symmetric(master_key);
  const size_t master_keylen = Buffer_get_size(master_key_buf);
  const uint8_t *master_key_bytes = Buffer_get_bytes(master_key_buf, NULL);

  // Allocate the correct amount of memory for the output bytes
  uint8_t *output_bytes = alloca(rounds * digestbytes);
  uint32_t result_len = 0;
  for (size_t i = 0; i < rounds; ++i) {
    // Copy over the count (NIST SP 800-108)
    memcpy(input_bytes, &i, sizeof(uint32_t));

    // Do the HMAC
    HMAC(parse_digest(cfg.digest_algorithm), master_key_bytes,
         (int)master_keylen, input_bytes, input_bytes_len,
         output_bytes + (i * digestbytes), &result_len);
  }

  // Get the first keylen bytes and uses them for the key
  peacemakr_key_t *out = PeacemakrKey_new_bytes(cfg, output_bytes, keybytes);

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
  EXPECT_NOT_NULL_RET(out, "Malloc failed!\n");

  out->m_cfg_ = cfg;
  out->m_contents_.asymm = NULL;

  BIO *bo = BIO_new_mem_buf(buf, (int)buflen);

  if (cfg.asymm_cipher == ECDH_P256 || cfg.asymm_cipher == ECDH_P384 ||
      cfg.asymm_cipher == ECDH_P521) {
    if (is_priv) {
      out->m_contents_.asymm = PEM_read_bio_PrivateKey(bo, NULL, NULL, NULL);
      EXPECT_NOT_NULL_CLEANUP_RET(
          out->m_contents_.asymm,
          {
            BIO_free(bo);
            PeacemakrKey_free(out);
          },
          "PEM_read_bio_ECPrivateKey failed\n");
    } else {
      out->m_contents_.asymm = PEM_read_bio_PUBKEY(bo, NULL, NULL, NULL);
      EXPECT_NOT_NULL_CLEANUP_RET(
          out->m_contents_.asymm,
          {
            BIO_free(bo);
            PeacemakrKey_free(out);
          },
          "PEM_read_bio_EC_PUBKEY failed\n");
    }

  } else if (cfg.asymm_cipher == RSA_2048 || cfg.asymm_cipher == RSA_4096) {
    RSA *rsaKey = NULL;
    if (is_priv) {
      out->m_contents_.asymm = PEM_read_bio_PrivateKey(bo, NULL, NULL, NULL);
      EXPECT_NOT_NULL_CLEANUP_RET(
          out->m_contents_.asymm,
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
      EXPECT_NOT_NULL_CLEANUP_RET(
          out->m_contents_.asymm,
          {
            BIO_free(bo);
            PeacemakrKey_free(out);
            RSA_free(rsaKey);
          },
          "PEM_read_bio_PUBKEY failed\n");
    }
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

peacemakr_key_t *PeacemakrKey_dh_generate(peacemakr_key_t *my_key,
                                          peacemakr_key_t *peer_key) {
  EXPECT_NOT_NULL_RET(
      my_key, "Neither input to PeacemakrKey_dh_generate may be NULL\n");
  EXPECT_NOT_NULL_RET(
      peer_key, "Neither input to PeacemakrKey_dh_generate may be NULL\n");

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(my_key->m_contents_.asymm, NULL);
  EXPECT_NOT_NULL_RET(ctx, "Unable to initialize EVP_PKEY_CTX\n");

  if (EVP_PKEY_derive_init(ctx) <= 0) {
    PEACEMAKR_OPENSSL_LOG;
    return NULL;
  }

  if (EVP_PKEY_derive_set_peer(ctx, peer_key->m_contents_.asymm) <= 0) {
    PEACEMAKR_OPENSSL_LOG;
    return NULL;
  }

  size_t skeylen = 0;

  if (EVP_PKEY_derive(ctx, NULL, &skeylen) <= 0) {
    PEACEMAKR_OPENSSL_LOG;
    return NULL;
  }

  uint8_t skey[skeylen];

  if (EVP_PKEY_derive(ctx, skey, &skeylen) <= 0) {
    PEACEMAKR_OPENSSL_LOG;
    return NULL;
  }

  crypto_config_t symm_key_cfg = {.mode = SYMMETRIC,
                                  .asymm_cipher = NONE,
                                  .symm_cipher = my_key->m_cfg_.symm_cipher,
                                  .digest_algorithm =
                                      my_key->m_cfg_.digest_algorithm};

  uint8_t hash[SHA256_DIGEST_LENGTH];

  SHA256(skey, skeylen, hash);

  EVP_PKEY_CTX_free(ctx);
  return PeacemakrKey_new_bytes(symm_key_cfg, hash, SHA256_DIGEST_LENGTH);
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

  if (key->m_cfg_.mode != ASYMMETRIC) {
    PEACEMAKR_ERROR("Cannot serialize a symmetric key to PEM\n");
    return false;
  }

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

  if (key->m_cfg_.mode != ASYMMETRIC) {
    PEACEMAKR_ERROR("Cannot serialize a symmetric key to PEM\n");
    return false;
  }

  BIO *bio = BIO_new(BIO_s_mem());
  if (!PEM_write_bio_PUBKEY(bio, key->m_contents_.asymm)) {
    PEACEMAKR_OPENSSL_LOG;
    PEACEMAKR_ERROR("Failed to write the PublicKey\n");
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

bool PeacemakrKey_get_bytes(const peacemakr_key_t *key, uint8_t **buf,
                            size_t *bufsize) {
  if (key->m_cfg_.mode != SYMMETRIC) {
    PEACEMAKR_ERROR("Cannot export bytes of asymmetric key\n");
    return false;
  }

  *bufsize = Buffer_get_size(key->m_contents_.symm);
  *buf = calloc(*bufsize, sizeof(uint8_t));
  EXPECT_NOT_NULL_RET_VALUE(*buf, false, "calloc failed\n");

  memcpy(*buf, Buffer_get_bytes(key->m_contents_.symm, NULL), *bufsize);

  return true;
}
