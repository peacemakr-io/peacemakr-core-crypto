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
  buffer_t *m_contents_;
  EVP_PKEY *m_evp_pkey_;
};

typedef struct PeacemakrKey peacemakr_key_t;

#define GLUE(prefix, name) prefix##name
#define API(name) GLUE(PeacemakrKey_, name)

peacemakr_key_t *API(new)(crypto_config_t cfg, random_device_t rand) {
  peacemakr_key_t *out = malloc(sizeof(peacemakr_key_t));

  const EVP_CIPHER *cipher = parse_cipher(cfg.symm_cipher);
  size_t keylen = (size_t)EVP_CIPHER_key_length(cipher);

  out->m_contents_ = Buffer_new(keylen);
  Buffer_init_rand(out->m_contents_, &rand);

  if (cfg.mode == ASYMMETRIC) {
    out->m_evp_pkey_ = NULL;
    switch (cfg.asymm_cipher) {
    case NONE: {
      PEACEMAKR_WARNING(
          "asymmetric cipher not specified for asymmetric mode\n");
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
      if (keygen_inner(EVP_PKEY_RSA, &out->m_evp_pkey_, 2048) == false) {
        PEACEMAKR_ERROR("keygen failed\n");
        return NULL;
      }
      break;
    }
    case RSA_4096: {
      if (keygen_inner(EVP_PKEY_RSA, &out->m_evp_pkey_, 4096) == false) {
        PEACEMAKR_ERROR("keygen failed\n");
        return NULL;
      }
      break;
    }
    }
  }

  return out;
}

peacemakr_key_t *API(new_bytes)(crypto_config_t cfg, const uint8_t *buf) {
  peacemakr_key_t *out = malloc(sizeof(peacemakr_key_t));

  const EVP_CIPHER *cipher = parse_cipher(cfg.symm_cipher);
  size_t keylen = (size_t)EVP_CIPHER_key_length(cipher);

  out->m_contents_ = Buffer_new(keylen);
  Buffer_set_bytes(out->m_contents_, buf, keylen);

  if (cfg.mode == ASYMMETRIC) {
    out->m_evp_pkey_ = NULL;
    switch (cfg.asymm_cipher) {
    case NONE: {
      PEACEMAKR_WARNING(
          "asymmetric cipher not specified for asymmetric mode\n");
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
      if (keygen_inner(EVP_PKEY_RSA, &out->m_evp_pkey_, 2048) == false) {
        PEACEMAKR_ERROR("keygen failed\n");
        return NULL;
      }
      break;
    }
    case RSA_4096: {
      if (keygen_inner(EVP_PKEY_RSA, &out->m_evp_pkey_, 4096) == false) {
        PEACEMAKR_ERROR("keygen failed\n");
        return NULL;
      }
      break;
    }
    }
  }

  return out;
}

void API(free)(peacemakr_key_t *key) {
  if (key == NULL) {
    PEACEMAKR_INFO("key was null, no-op\n");
    return;
  }

  Buffer_free(key->m_contents_); // securely frees the memory
  free(key);
  key = NULL;
}

const buffer_t *API(symmetric)(const peacemakr_key_t *key) {
  return key->m_contents_;
}

EVP_PKEY *API(asymmetric)(const peacemakr_key_t *key) {
  if (key->m_evp_pkey_ == NULL) {
    PEACEMAKR_DEBUG("key is in symmetric mode\n");
    return NULL;
  }

  return key->m_evp_pkey_;
}