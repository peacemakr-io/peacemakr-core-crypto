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
#include <openssl/rsa.h>
#include <openssl/pem.h>

static bool keygen_inner(int key_type, EVP_PKEY **pkey, int rsa_bits) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(key_type, NULL);
  if (!ctx) {
    PEACEMAKR_ERROR("EVP_PKEY_CTX_new_id failed\n");
    return false;
  }

  int rc = EVP_PKEY_keygen_init(ctx);
  if (rc <= 0) {
    PEACEMAKR_ERROR("EVP_PKEY_keygen_init failed with rc %d\n", rc);
    return false;
  }

  if (key_type == EVP_PKEY_RSA && rsa_bits > 0 &&
      (rsa_bits == 2048 || rsa_bits == 4096)) {
    rc = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, rsa_bits);
    if (rc <= 0) {
      PEACEMAKR_ERROR("set_rsa_keygen_bits failed\n");
      return false;
    }
  }

  rc = EVP_PKEY_keygen(ctx, pkey);
  if (rc <= 0) {
    PEACEMAKR_ERROR("EVP_PKEY_keygen failed\n");
    return false;
  }

  return true;
}

struct PeacemakrKey {
  encryption_mode m_mode_;
  union {
    buffer_t *symm;
    EVP_PKEY *asymm;
  } m_contents_;
};

typedef struct PeacemakrKey peacemakr_key_t;

#define GLUE(prefix, name) prefix##name
#define API(name) GLUE(PeacemakrKey_, name)

peacemakr_key_t *API(new)(crypto_config_t cfg, random_device_t *rand) {
  if (rand == NULL) {
    PEACEMAKR_ERROR("Cannot create a new key without a source of randomness\n");
    return NULL;
  }

  peacemakr_key_t *out = malloc(sizeof(peacemakr_key_t));
  out->m_mode_ = cfg.mode;

  switch (cfg.mode) {
  case SYMMETRIC: {
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
      API(free)(out);
      return NULL;
    }
      //    case EC25519: {
      //      if (keygen_inner(NID_X25519, &out->m_evp_pkey_, 0) == false) {
      //        PEACEMAKR_ERROR("keygen failed\n");
      //        return NULL;
      //      }
      //      break;
      //    }
    case RSA_2048: {
      if (keygen_inner(EVP_PKEY_RSA, &out->m_contents_.asymm, 2048) == false) {
        PEACEMAKR_ERROR("keygen failed\n");
        API(free)(out);
        return NULL;
      }
      break;
    }
    case RSA_4096: {
      if (keygen_inner(EVP_PKEY_RSA, &out->m_contents_.asymm, 4096) == false) {
        PEACEMAKR_ERROR("keygen failed\n");
        API(free)(out);
        return NULL;
      }
      break;
    }
    }
    return out;
  }
  }

  PEACEMAKR_ERROR("unknown failure\n");
  API(free)(out);
  return NULL;
}

peacemakr_key_t *API(new_bytes)(crypto_config_t cfg, const uint8_t *buf) {
  if (cfg.mode == ASYMMETRIC) {
    PEACEMAKR_ERROR("Can't set raw bytes of asymmetric key, this call only "
                    "works in symmetric mode\n");
    return NULL;
  }

  if (buf == NULL) {
    PEACEMAKR_ERROR("buffer is null\n");
    return NULL;
  }

  peacemakr_key_t *out = malloc(sizeof(peacemakr_key_t));
  out->m_mode_ = cfg.mode;

  const EVP_CIPHER *cipher = parse_cipher(cfg.symm_cipher);
  size_t keylen = (size_t)EVP_CIPHER_key_length(cipher);

  out->m_contents_.symm = Buffer_new(keylen);
  Buffer_set_bytes(out->m_contents_.symm, buf, keylen);

  return out;
}

peacemakr_key_t *API(new_pkey)(crypto_config_t cfg, const EVP_PKEY *buf) {
  if (cfg.mode == SYMMETRIC) {
    PEACEMAKR_ERROR("Can't set a new EVP_PKEY for symmetric crypto\n");
    return NULL;
  }

  if (buf == NULL) {
    PEACEMAKR_ERROR("pkey is NULL\n");
    return NULL;
  }

  peacemakr_key_t *out = malloc(sizeof(peacemakr_key_t));
  out->m_mode_ = cfg.mode;

  out->m_contents_.asymm = EVP_PKEY_new();
  int rc = EVP_PKEY_copy_parameters(out->m_contents_.asymm, buf);
  if (rc != 1) {
    PEACEMAKR_ERROR("EVP_PKEY parameter copy failed\n");
    API(free)(out);
    return NULL;
  }

  return out;
}

peacemakr_key_t *API(new_pem_pub)(crypto_config_t cfg, const char *buf, const size_t buflen) {
  if (buf == NULL || buflen == 0) {
    PEACEMAKR_ERROR("buf was null or buflen was 0");
    return NULL;
  }

  BIO* bo = BIO_new(BIO_s_mem());
  BIO_write(bo, buf, (int)buflen);

  EVP_PKEY* pkey = NULL;
  PEM_read_bio_PUBKEY(bo, &pkey, 0, 0);

  BIO_free(bo);

  return API(new_pkey)(cfg, pkey);
}

peacemakr_key_t *API(new_pem_priv)(crypto_config_t cfg, const char *buf, const size_t buflen) {
  if (buf == NULL || buflen == 0) {
    PEACEMAKR_ERROR("buf was null or buflen was 0");
    return NULL;
  }

  BIO* bo = BIO_new(BIO_s_mem());
  BIO_write(bo, buf, (int)buflen);

  EVP_PKEY* pkey = NULL;
  PEM_read_bio_PrivateKey(bo, &pkey, 0, 0);

  BIO_free(bo);

  return API(new_pkey)(cfg, pkey);
}

void API(free)(peacemakr_key_t *key) {
  if (key == NULL) {
    PEACEMAKR_INFO("key was null, no-op\n");
    return;
  }

  switch (key->m_mode_) {
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

const buffer_t *API(symmetric)(const peacemakr_key_t *key) {
  if (key->m_mode_ != SYMMETRIC) {
    PEACEMAKR_ERROR(
        "Attempting to access the symmetric part of an asymmetric key\n");
    return NULL;
  }

  return key->m_contents_.symm;
}

EVP_PKEY *API(asymmetric)(const peacemakr_key_t *key) {
  if (key->m_mode_ != ASYMMETRIC) {
    PEACEMAKR_ERROR(
        "Attempting to access the asymmetric part of a symmetric key\n");
    return NULL;
  }

  return key->m_contents_.asymm;
}