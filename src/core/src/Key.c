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
#include <random.h>

#include <stdlib.h>
#include <stdbool.h>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

static const EVP_CIPHER *parse_cipher(crypto_config_t cfg) {

  switch (cfg.mode) {
    case SYMMETRIC: {
      switch (cfg.symm_cipher) {
        case AES_128_GCM:
          return EVP_aes_128_gcm();
        case AES_192_GCM:
          return EVP_aes_192_gcm();
        case AES_256_GCM:
          return EVP_aes_256_gcm();
        case AES_128_CBC:
          return EVP_aes_128_cbc();
        case AES_192_CBC:
          return EVP_aes_192_cbc();
        case AES_256_CBC:
          return EVP_aes_256_cbc();
        case AES_128_CFB:
          return EVP_aes_128_cfb();
        case AES_192_CFB:
          return EVP_aes_192_cfb();
        case AES_256_CFB:
          return EVP_aes_256_cfb();
        case AES_128_ECB:
          return EVP_aes_128_ecb();
        case AES_192_ECB:
          return EVP_aes_192_ecb();
        case AES_256_ECB:
          return EVP_aes_256_ecb();
        case AES_128_OFB:
          return EVP_aes_128_ofb();
        case AES_192_OFB:
          return EVP_aes_192_ofb();
        case AES_256_OFB:
          return EVP_aes_256_ofb();
        case AES_128_CTR:
          return EVP_aes_128_ctr();
        case AES_192_CTR:
          return EVP_aes_192_ctr();
        case AES_256_CTR:
          return EVP_aes_256_ctr();
        case AES_128_CCM:
          return EVP_aes_128_ccm();
        case AES_192_CCM:
          return EVP_aes_192_ccm();
        case AES_256_CCM:
          return EVP_aes_256_ccm();
        case AES_128_WRAP:
          return EVP_aes_128_wrap();
        case AES_192_WRAP:
          return EVP_aes_192_wrap();
        case AES_256_WRAP:
          return EVP_aes_256_wrap();
        case AES_128_WRAP_PAD:
          return EVP_aes_128_wrap_pad();
        case AES_192_WRAP_PAD:
          return EVP_aes_192_wrap_pad();
        case AES_256_WRAP_PAD:
          return EVP_aes_256_wrap_pad();
        case AES_128_XTS:
          return EVP_aes_128_xts();
        case AES_256_XTS:
          return EVP_aes_256_xts();
        case AES_128_CBC_HMAC_SHA1:
          return EVP_aes_256_cbc_hmac_sha1();
        case AES_256_CBC_HMAC_SHA1:
          return EVP_aes_256_cbc_hmac_sha1();
        case AES_128_CBC_HMAC_SHA256:
          return EVP_aes_256_cbc_hmac_sha256();
        case AES_256_CBC_HMAC_SHA256:
          return EVP_aes_256_cbc_hmac_sha256();
        case CHACHA20:
          return EVP_chacha20();
        case CHACHA20_POLY1305:
          return EVP_chacha20_poly1305();
      }
    }
    case ASYMMETRIC: {
      PEACEMAKR_WARNING("no EVP_CIPHER for asymmetric cipher");
      break;
    }
  }

  return NULL;
}

static bool keygen_inner(int key_type, EVP_PKEY **pkey, int rsa_bits) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(key_type, NULL);
  if (!ctx) {
    PEACEMAKR_ERROR("EVP_PKEY_CTX_new_id(NID_X25519) failed");
    return false;
  }

  int rc = EVP_PKEY_keygen_init(ctx);
  if (rc <= 0) {
    PEACEMAKR_ERROR("EVP_PKEY_keygen_init failed");
    return false;
  }

  if (key_type == EVP_PKEY_RSA && rsa_bits > 0 &&
      (rsa_bits == 2048 || rsa_bits == 4096)) {
    rc = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, rsa_bits);
    if (rc == 0) {
      PEACEMAKR_ERROR("set_rsa_keygen_bits failed");
      return false;
    }
  }

  rc = EVP_PKEY_keygen(ctx, pkey);
  if (rc <= 0) {
    PEACEMAKR_ERROR("EVP_PKEY_keygen failed");
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

  const EVP_CIPHER *cipher = parse_cipher(cfg);
  size_t keylen = (size_t)EVP_CIPHER_key_length(cipher);

  out->m_contents_ = Buffer_new(keylen);
  Buffer_init_rand(out->m_contents_, &rand);

  if (cfg.mode == ASYMMETRIC) {
    switch (cfg.asymm_cipher) {
    case NONE: {
      PEACEMAKR_WARNING("asymmetric cipher not specified for asymmetric mode");
      return NULL;
    }
    case EC25519: {
      if (keygen_inner(NID_X25519, &out->m_evp_pkey_, 0) == false) {
        PEACEMAKR_ERROR("keygen failed");
        return NULL;
      }
      break;
    }
    case RSA_2048: {
      if (keygen_inner(EVP_PKEY_RSA, &out->m_evp_pkey_, 2048) == false) {
        PEACEMAKR_ERROR("keygen failed");
        return NULL;
      }
      break;
    }
    case RSA_4096: {
      if (keygen_inner(EVP_PKEY_RSA, &out->m_evp_pkey_, 4096) == false) {
        PEACEMAKR_ERROR("keygen failed");
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
    PEACEMAKR_INFO("key was null, no-op");
    return;
  }

  Buffer_free(key->m_contents_); // securely frees the memory
  free(key);
  key = NULL;
}