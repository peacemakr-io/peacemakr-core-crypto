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

#include <crypto.h>
#include <openssl/dh.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

static bool keygen_inner(int key_type, EVP_PKEY **pkey, int rsa_bits) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(key_type, NULL);
  EXPECT_NOT_NULL_RET_VALUE(ctx, false, "EVP_PKEY_CTX_new_id failed\n")

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
  default:
    PEACEMAKR_ERROR("Unknown curve specified: %d", curve);
    return false;
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

peacemakr_key_t *peacemakr_key_new_asymmetric(asymmetric_cipher cipher,
                                              symmetric_cipher symm_cipher,
                                              random_device_t *rand) {
  EXPECT_NOT_NULL_RET(
      rand, "Cannot create a new key without a source of randomness\n")

  peacemakr_key_t *out = malloc(sizeof(peacemakr_key_t));
  EXPECT_NOT_NULL_RET(out, "Malloc failed\n")

  out->m_cfg_.mode = ASYMMETRIC;
  out->m_cfg_.symm_cipher = SYMMETRIC_UNSPECIFIED;
  out->m_cfg_.asymm_cipher = cipher;
  out->m_cfg_.digest_algorithm = DIGEST_UNSPECIFIED;

  out->m_contents_.asymm = NULL;

  if (symm_cipher == SYMMETRIC_UNSPECIFIED && cipher >= RSA_2048 &&
      cipher <= RSA_4096) {
    PEACEMAKR_ERROR("Must specify a symmetric algorithm for RSA keys\n");
    peacemakr_key_free(out);
    return NULL;
  }

  out->m_contents_.asymm = NULL;
  switch (cipher) {
  case ASYMMETRIC_UNSPECIFIED: {
    PEACEMAKR_ERROR("asymmetric cipher not specified for asymmetric mode\n");
    peacemakr_key_free(out);
    return NULL;
  }
  case RSA_2048: {
    out->m_cfg_.symm_cipher = symm_cipher;
    if (keygen_inner(EVP_PKEY_RSA, &out->m_contents_.asymm, 2048) == false) {
      PEACEMAKR_ERROR("keygen failed\n");
      peacemakr_key_free(out);
      return NULL;
    }
    break;
  }
  case RSA_4096: {
    out->m_cfg_.symm_cipher = symm_cipher;
    if (keygen_inner(EVP_PKEY_RSA, &out->m_contents_.asymm, 4096) == false) {
      PEACEMAKR_ERROR("keygen failed\n");
      peacemakr_key_free(out);
      return NULL;
    }
    break;
  }
  case ECDH_P256: {
    if (dh_keygen_inner(&out->m_contents_.asymm, P256) == false) {
      PEACEMAKR_ERROR("keygen failed\n");
      peacemakr_key_free(out);
      return NULL;
    }
    break;
  }
  case ECDH_P384: {
    if (dh_keygen_inner(&out->m_contents_.asymm, P384) == false) {
      PEACEMAKR_ERROR("keygen failed\n");
      peacemakr_key_free(out);
      return NULL;
    }
    break;
  }
  case ECDH_P521: {
    if (dh_keygen_inner(&out->m_contents_.asymm, P521) == false) {
      PEACEMAKR_ERROR("keygen failed\n");
      peacemakr_key_free(out);
      return NULL;
    }
    break;
  }
  default: {
    PEACEMAKR_ERROR("unknown asymmetric algorithm\n");
    peacemakr_key_free(out);
    return NULL;
  }
  }
  return out;
}

peacemakr_key_t *peacemakr_key_new_symmetric(symmetric_cipher cipher,
                                             random_device_t *rand) {
  EXPECT_NOT_NULL_RET(
      rand, "Cannot create a new key without a source of randomness\n")

  peacemakr_key_t *out = malloc(sizeof(peacemakr_key_t));
  EXPECT_NOT_NULL_RET(out, "Malloc failed\n")

  out->m_cfg_.mode = SYMMETRIC;
  out->m_cfg_.symm_cipher = cipher;
  out->m_cfg_.asymm_cipher = ASYMMETRIC_UNSPECIFIED;
  out->m_cfg_.digest_algorithm = DIGEST_UNSPECIFIED;

  out->m_contents_.symm = NULL;

  const EVP_CIPHER *evp_cipher = parse_cipher(cipher);
  size_t keylen = (size_t)EVP_CIPHER_key_length(evp_cipher);

  out->m_contents_.symm = buffer_new(keylen);
  buffer_init_rand(out->m_contents_.symm, rand);
  return out;
}

peacemakr_key_t *peacemakr_key_new_bytes(symmetric_cipher cipher,
                                         const uint8_t *buf,
                                         const size_t buf_len) {
  EXPECT_NOT_NULL_RET(buf, "buffer is null\n")

  const EVP_CIPHER *evp_cipher = parse_cipher(cipher);
  size_t keylen = (size_t)EVP_CIPHER_key_length(evp_cipher);
  EXPECT_TRUE_RET((buf_len >= keylen), "byte buffer was too small\n")

  peacemakr_key_t *out = malloc(sizeof(peacemakr_key_t));
  EXPECT_NOT_NULL_RET(out, "Malloc failed!\n")

  out->m_cfg_.mode = SYMMETRIC;
  out->m_cfg_.symm_cipher = cipher;
  out->m_cfg_.asymm_cipher = ASYMMETRIC_UNSPECIFIED;
  out->m_cfg_.digest_algorithm = DIGEST_UNSPECIFIED;

  out->m_contents_.symm = NULL;

  out->m_contents_.symm = buffer_new(keylen);
  buffer_set_bytes(out->m_contents_.symm, buf, keylen);

  return out;
}

peacemakr_key_t *peacemakr_key_new_from_password(
    symmetric_cipher cipher, message_digest_algorithm digest,
    const uint8_t *password, const size_t password_len, const uint8_t *salt,
    const size_t salt_len, const size_t iteration_count) {
  EXPECT_NOT_NULL_RET(password, "buffer is null\n")
  EXPECT_TRUE_RET((password_len >= 0),
                  "Password size cannot be less than or equal to zero\n")
  EXPECT_NOT_NULL_RET(salt, "Random device cannot be null\n")
  EXPECT_TRUE_RET((salt_len >= 0),
                  "Salt size cannot be less than or equal to zero\n")
  EXPECT_TRUE_RET((iteration_count >= 0),
                  "Iteration count cannot be less than or equal to zero\n")

  const EVP_CIPHER *evp_cipher = parse_cipher(cipher);
  const EVP_MD *mda = parse_digest(digest);

  const size_t keylen = EVP_CIPHER_key_length(evp_cipher);
  uint8_t *keybuf = alloca(keylen);

  // Create the key
  if (1 != PKCS5_PBKDF2_HMAC((const char *)password, password_len, salt,
                             salt_len, iteration_count, mda, keylen, keybuf)) {
    PEACEMAKR_OPENSSL_LOG;
    return NULL;
  }

  return peacemakr_key_new_bytes(cipher, keybuf, keylen);
}

peacemakr_key_t *
peacemakr_key_new_from_master(symmetric_cipher cipher,
                              message_digest_algorithm digest,
                              const peacemakr_key_t *master_key,
                              const uint8_t *key_id, const size_t key_id_len) {

  // digest length in bytes
  size_t digestbytes = get_digest_len(digest);
  if (digestbytes == 0) {
    PEACEMAKR_ERROR("Unable to parse digest algorithm\n");
    return NULL;
  }
  // digestlen should be in bits
  size_t digestbits = digestbytes * 8;

  // Get the number of bits required for the key
  int keybytes_int = EVP_CIPHER_key_length(parse_cipher(cipher));
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
  const buffer_t *master_key_buf = peacemakr_key_symmetric(master_key);
  const size_t master_keylen = buffer_get_size(master_key_buf);
  const uint8_t *master_key_bytes = buffer_get_bytes(master_key_buf, NULL);

  // Allocate the correct amount of memory for the output bytes
  uint8_t *output_bytes = alloca(rounds * digestbytes);
  uint32_t result_len = 0;
  for (size_t i = 0; i < rounds; ++i) {
    // Copy over the count (NIST SP 800-108)
    memcpy(input_bytes, &i, sizeof(uint32_t));

    // Do the HMAC
    HMAC(parse_digest(digest), master_key_bytes, (int)master_keylen,
         input_bytes, input_bytes_len, output_bytes + (i * digestbytes),
         &result_len);
  }

  // Get the first keylen bytes and uses them for the key
  return peacemakr_key_new_bytes(cipher, output_bytes, keybytes);
}

peacemakr_key_t *peacemakr_key_new_pem(symmetric_cipher symm_cipher,
                                       const char *buf, size_t buflen,
                                       bool is_priv) {

  EXPECT_TRUE_RET((buf != NULL && buflen > 0), "buf was null or buflen was 0\n")
  EXPECT_TRUE_RET((buflen <= INT_MAX),
                  "Length of passed pem file is greater than INT_MAX\n")

  peacemakr_key_t *out = malloc(sizeof(peacemakr_key_t));
  EXPECT_NOT_NULL_RET(out, "Malloc failed!\n")

  out->m_cfg_.mode = ASYMMETRIC;
  out->m_cfg_.symm_cipher = symm_cipher;
  out->m_cfg_.digest_algorithm = DIGEST_UNSPECIFIED;

  out->m_contents_.asymm = NULL;

  BIO *bo = BIO_new_mem_buf(buf, (int)buflen);

  if (is_priv) {
    out->m_contents_.asymm = PEM_read_bio_PrivateKey(bo, NULL, NULL, NULL);
    EXPECT_NOT_NULL_CLEANUP_RET(
        out->m_contents_.asymm,
        {
          BIO_free(bo);
          peacemakr_key_free(out);
        },
        "PEM_read_bio_ECPrivateKey failed\n")
  } else {
    out->m_contents_.asymm = PEM_read_bio_PUBKEY(bo, NULL, NULL, NULL);
    EXPECT_NOT_NULL_CLEANUP_RET(
        out->m_contents_.asymm,
        {
          BIO_free(bo);
          peacemakr_key_free(out);
        },
        "PEM_read_bio_EC_PUBKEY failed\n")
  }

  int pkeyID = EVP_PKEY_id(out->m_contents_.asymm);

  switch (pkeyID) {
  // ECDH
  case NID_X9_62_id_ecPublicKey: {
    EC_KEY *k = EVP_PKEY_get0_EC_KEY(out->m_contents_.asymm);
    const EC_GROUP *group = EC_KEY_get0_group(k);
    int curve_name = EC_GROUP_get_curve_name(group);
    if (curve_name == NID_X9_62_prime256v1) {
      out->m_cfg_.asymm_cipher = ECDH_P256;
    } else if (curve_name == NID_secp384r1) {
      out->m_cfg_.asymm_cipher = ECDH_P384;
    } else if (curve_name == NID_secp521r1) {
      out->m_cfg_.asymm_cipher = ECDH_P521;
    } else {
      PEACEMAKR_ERROR("Unknown EC key size\n");
      BIO_free(bo);
      peacemakr_key_free(out);
      return NULL;
    }

    break;
  }

  // RSA
  case NID_rsaEncryption:
  case NID_rsa: {
    RSA *rsa = EVP_PKEY_get0_RSA(out->m_contents_.asymm);
    int rsa_size = RSA_size(rsa);

    if (rsa_size == 256) {
      out->m_cfg_.asymm_cipher = RSA_2048;
    } else if (rsa_size == 512) {
      out->m_cfg_.asymm_cipher = RSA_4096;
    } else {
      PEACEMAKR_ERROR("Unknown RSA size\n");
      BIO_free(bo);
      peacemakr_key_free(out);
      return NULL;
    }

    break;
  }

  // And by default we don't know
  default: {
    PEACEMAKR_ERROR("Unknown asymmetric algorithm\n");
    BIO_free(bo);
    peacemakr_key_free(out);
    return NULL;
  }
  }

  BIO_free(bo);

  return out;
}

peacemakr_key_t *peacemakr_key_new_pem_pub(symmetric_cipher symm_cipher,
                                           const char *buf, size_t buflen) {
  return peacemakr_key_new_pem(symm_cipher, buf, buflen, false);
}

peacemakr_key_t *peacemakr_key_new_pem_priv(symmetric_cipher symm_cipher,
                                            const char *buf, size_t buflen) {
  return peacemakr_key_new_pem(symm_cipher, buf, buflen, true);
}

peacemakr_key_t *peacemakr_key_dh_generate(symmetric_cipher cipher,
                                           const peacemakr_key_t *my_key,
                                           const peacemakr_key_t *peer_key) {
  EXPECT_NOT_NULL_RET(
      my_key, "Neither input to peacemakr_key_dh_generate may be NULL\n")
  EXPECT_NOT_NULL_RET(
      peer_key, "Neither input to peacemakr_key_dh_generate may be NULL\n")
  EXPECT_TRUE_RET((cipher != SYMMETRIC_UNSPECIFIED),
                  "Cannot generate a DH key with an unspecified cipher\n")

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(my_key->m_contents_.asymm, NULL);
  EXPECT_NOT_NULL_RET(ctx, "Unable to initialize EVP_PKEY_CTX\n")

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

  uint8_t hash[SHA256_DIGEST_LENGTH];
  (void)SHA256(skey, skeylen, hash);

  EVP_PKEY_CTX_free(ctx);
  return peacemakr_key_new_bytes(cipher, hash, SHA256_DIGEST_LENGTH);
}

void peacemakr_key_free(peacemakr_key_t *key) {
  EXPECT_NOT_NULL_RET_NONE(key, "key was null\n")

  if (key->m_contents_.symm == NULL) {
    free(key);
    key = NULL;
    return;
  }

  switch (key->m_cfg_.mode) {
  case SYMMETRIC: {
    buffer_free(key->m_contents_.symm); // securely frees the memory
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

crypto_config_t peacemakr_key_get_config(const peacemakr_key_t *key) {
  return key->m_cfg_;
}

bool peacemakr_key_set_symmetric_cipher(peacemakr_key_t *key,
                                        symmetric_cipher cipher) {

  if (key->m_cfg_.mode != ASYMMETRIC) {
    PEACEMAKR_ERROR(
        "Cannot override the symmetric cipher of a symmetric key\n");
    return false;
  }

  if (key->m_cfg_.symm_cipher != SYMMETRIC_UNSPECIFIED) {
    PEACEMAKR_ERROR("Cannot override the symmetric cipher when it's already "
                    "been specified\n");
    return false;
  }

  if (key->m_cfg_.asymm_cipher < RSA_2048 ||
      key->m_cfg_.asymm_cipher > RSA_4096) {
    PEACEMAKR_ERROR(
        "ECDH keys do not support overriding the symmetric cipher\n");
    return false;
  }

  key->m_cfg_.symm_cipher = cipher;
  return true;
}

const buffer_t *peacemakr_key_symmetric(const peacemakr_key_t *key) {
  EXPECT_TRUE_RET(
      (key->m_cfg_.mode == SYMMETRIC),
      "Attempting to access the symmetric part of an asymmetric key\n")

  return key->m_contents_.symm;
}

EVP_PKEY *peacemakr_key_asymmetric(const peacemakr_key_t *key) {
  EXPECT_TRUE_RET(
      (key->m_cfg_.mode == ASYMMETRIC),
      "Attempting to access the asymmetric part of a symmetric key\n")

  return key->m_contents_.asymm;
}

bool peacemakr_key_priv_to_pem(const peacemakr_key_t *key, char **buf,
                               size_t *bufsize) {
  EXPECT_NOT_NULL_RET_VALUE(key, false, "Cannot serialize a NULL key\n")
  EXPECT_NOT_NULL_RET_VALUE(buf, false, "Cannot serialize into a NULL buffer\n")
  EXPECT_NOT_NULL_RET_VALUE(bufsize, false,
                            "Cannot serialize into a NULL bufsize\n")

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

bool peacemakr_key_pub_to_pem(const peacemakr_key_t *key, char **buf,
                              size_t *bufsize) {
  EXPECT_NOT_NULL_RET_VALUE(key, false, "Cannot serialize a NULL key\n")
  EXPECT_NOT_NULL_RET_VALUE(buf, false, "Cannot serialize into a NULL buffer\n")
  EXPECT_NOT_NULL_RET_VALUE(bufsize, false,
                            "Cannot serialize into a NULL bufsize\n")

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

bool peacemakr_key_get_bytes(const peacemakr_key_t *key, uint8_t **buf,
                             size_t *bufsize) {
  if (key->m_cfg_.mode != SYMMETRIC) {
    PEACEMAKR_ERROR("Cannot export bytes of asymmetric key\n");
    return false;
  }

  *bufsize = buffer_get_size(key->m_contents_.symm);
  *buf = calloc(*bufsize, sizeof(uint8_t));
  EXPECT_NOT_NULL_RET_VALUE(*buf, false, "calloc failed\n")

  memcpy(*buf, buffer_get_bytes(key->m_contents_.symm, NULL), *bufsize);

  return true;
}
