//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include "crypto.h"

#include "Buffer.h"
#include "CiphertextBlob.h"
#include "EVPHelper.h"
#include "Logging.h"
#include "b64.h"

#include <memory.h>

#define _PEACEMAKR_MAGIC_ (uint32_t)1054

// HMAC-SHA512 needs a 64 byte key. Shorter HMAC versions will truncate.
static const uint8_t PEACEMAKR_MAGIC_KEY[64] =
    "7d3rAfIHtCbYLm1OY6IRjvoBdqw2QdyvPIECF4Aczs2LgiShn8CeO8c21Q+GMuGf";

static peacemakr_key_t *get_hmac_key(message_digest_algorithm digest_algo) {
  crypto_config_t hmac_cfg = {.mode = SYMMETRIC,
                              .symm_cipher = CHACHA20_POLY1305,
                              .asymm_cipher = NONE,
                              .digest_algorithm = digest_algo};
  peacemakr_key_t *hmac_key =
      PeacemakrKey_new_bytes(hmac_cfg, PEACEMAKR_MAGIC_KEY, 32);
  return hmac_key;
}

/*
 * Peacemakr message serialization format:
 *
 * (0) Magic number (32 bits)
 * (1) Size of the message until the digest (64 bits)
 * (2) Digest algorithm (8 bits)
 * (3) Version (32 bits)
 * (4) Encryption mode (8 bits)
 * (5) Symmetric cipher algorithm (8 bits)
 * (6) Asymmetric cipher algorithm (8 bits)
 * (7) Encrypted key (128, 192, or 256 bits)
 * (8) IV (usually 96 bits, always <= 128 bits)
 * (9) Tag (128 bits)
 * (10) AAD
 * (11) Ciphertext
 * (12) Message HMAC (224, 256, 384, or 512 bits)
 */

uint8_t *peacemakr_serialize(ciphertext_blob_t *cipher, size_t *out_size) {
  EXPECT_TRUE_RET((cipher != NULL && out_size != NULL),
                  "cipher or out_size was null in call to serialize\n");

  size_t buffer_len = sizeof(uint32_t); // magic number
  buffer_len += sizeof(uint64_t);       // size of message up until digest
  buffer_len += sizeof(uint8_t);        // digest algo
  // version
  buffer_len += sizeof(uint32_t);
  // encryption mode, symm_cipher, asymm_cipher
  buffer_len += sizeof(uint8_t) * 3;

  const buffer_t *encrypted_key = CiphertextBlob_encrypted_key(cipher);
  buffer_len += Buffer_get_serialized_size(encrypted_key);

  const buffer_t *iv = CiphertextBlob_iv(cipher);
  buffer_len += Buffer_get_serialized_size(iv);

  const buffer_t *tag = CiphertextBlob_tag(cipher);
  buffer_len += Buffer_get_serialized_size(tag);

  const buffer_t *aad = CiphertextBlob_aad(cipher);
  buffer_len += Buffer_get_serialized_size(aad);

  const buffer_t *ciphertext = CiphertextBlob_ciphertext(cipher);
  buffer_len += Buffer_get_serialized_size(ciphertext);

  const buffer_t *signature = CiphertextBlob_signature(cipher);
  buffer_len += Buffer_get_serialized_size(signature);

  // We will digest the message and set it at the end
  buffer_len += sizeof(uint64_t);
  size_t digest_len = get_digest_len(CiphertextBlob_digest_algo(cipher));
  buffer_len += digest_len;

  uint8_t *buf = alloca(buffer_len * sizeof(uint8_t));
  size_t current_pos = 0;

  // magic
  uint32_t magic = htonl(_PEACEMAKR_MAGIC_);
  memcpy(buf, &magic, sizeof(uint32_t));
  current_pos += sizeof(uint32_t);

  // len until digest
  memset((buf + current_pos), 0, sizeof(uint64_t));
  current_pos += sizeof(uint64_t);

  // digest algo
  uint8_t digest_algo = CiphertextBlob_digest_algo(cipher);
  *(buf + current_pos) = digest_algo;
  current_pos += sizeof(uint8_t);

  // version
  uint32_t version = htonl(CiphertextBlob_version(cipher));
  memcpy(buf + current_pos, &version, sizeof(uint32_t));
  current_pos += sizeof(uint32_t);

  // encryption mode
  uint8_t encryption_mode = CiphertextBlob_encryption_mode(cipher);
  *(buf + current_pos) = encryption_mode;
  current_pos += sizeof(uint8_t);

  // symm cipher
  uint8_t symm_cipher = CiphertextBlob_symm_cipher(cipher);
  *(buf + current_pos) = symm_cipher;
  current_pos += sizeof(uint8_t);

  // asymm cipher
  uint8_t asymm_cipher = CiphertextBlob_asymm_cipher(cipher);
  *(buf + current_pos) = asymm_cipher;
  current_pos += sizeof(uint8_t);

  // encrypted key
  size_t ekey_len = Buffer_serialize(encrypted_key, buf + current_pos);
  current_pos += ekey_len;

  // iv
  size_t ivlen = Buffer_serialize(iv, buf + current_pos);
  current_pos += ivlen;

  // tag
  size_t taglen = Buffer_serialize(tag, buf + current_pos);
  current_pos += taglen;

  // aad
  size_t aadlen = Buffer_serialize(aad, buf + current_pos);
  current_pos += aadlen;

  // ciphertext
  size_t ciphertextlen = Buffer_serialize(ciphertext, buf + current_pos);
  current_pos += ciphertextlen;

  // signature
  size_t signaturelen = Buffer_serialize(signature, buf + current_pos);
  current_pos += signaturelen;

  // set the size of the buffer until the digest (at offset sizeof(uint32_t))
  uint64_t curr_pos = htonl(current_pos);
  memcpy(buf + sizeof(uint32_t), &curr_pos, sizeof(uint64_t));

  // digest the message
  buffer_t *message_digest = Buffer_new(digest_len);

  // get our hmac key
  peacemakr_key_t *hmac_key = get_hmac_key(CiphertextBlob_digest_algo(cipher));

  // Digest the message
  size_t digest_out_size = 0;
  uint8_t *raw_digest = peacemakr_hmac(CiphertextBlob_digest_algo(cipher), hmac_key,
                                   buf, current_pos, &digest_out_size);

  // Make sure we didn't do a stupid
  EXPECT_TRUE_RET(digest_out_size == digest_len, "Computed HMAC was of the incorrect size\n");

  // Store it
  Buffer_set_bytes(message_digest, raw_digest, digest_out_size);

  // Clean up
  free(raw_digest);
  PeacemakrKey_free(hmac_key);

  // Append the digest
  size_t digestlen = Buffer_serialize(message_digest, buf + current_pos);
  current_pos += digestlen;

  CiphertextBlob_free(cipher);
  cipher = NULL;

  return (uint8_t *)b64_encode(buf, current_pos, out_size);
}

ciphertext_blob_t *peacemakr_deserialize(const uint8_t *b64_serialized_cipher,
                                         size_t serialized_len,
                                         crypto_config_t *cfg) {

  EXPECT_TRUE_RET((b64_serialized_cipher != NULL && serialized_len != 0),
                  "b64 serialized cipher was NULL or serialized len was 0\n");
  EXPECT_NOT_NULL_RET(
      cfg, "need to store the deserialized configuration somewhere\n");

  uint8_t *serialized_cipher = alloca(serialized_len);
  EXPECT_NOT_NULL_RET(serialized_cipher, "failed to allocate serialize_cipher")
  
  int rc = b64_decode((const char *)b64_serialized_cipher, serialized_cipher,
                      serialized_len);
  EXPECT_TRUE_RET((rc == 1), "b64 decode failed\n");

  size_t current_position = 0;

  // magic
  uint32_t magic = ntohl(*(uint32_t *)serialized_cipher);
  EXPECT_TRUE_RET((magic == _PEACEMAKR_MAGIC_),
                  "magic number corrupted/missing, aborting\n");
  current_position += sizeof(uint32_t);

  // len until digest
  uint64_t len_before_digest =
      ntohl(*(uint64_t *)(serialized_cipher + current_position));
  current_position += sizeof(uint64_t);

  // Something is bad
  EXPECT_TRUE_RET(len_before_digest < serialized_len,
                  "corrupted length in message, aborting\n");

  // digest algo
  uint8_t digest_algo = *(serialized_cipher + current_position);
  current_position += sizeof(uint8_t);

  { // Check that the message digests are equal
    const EVP_MD *digest_algorithm = parse_digest(digest_algo);
    EXPECT_NOT_NULL_RET(digest_algorithm,
                        "corrupted digest algorithm, aborting\n");

    uint64_t digestlen = (uint64_t)EVP_MD_size(digest_algorithm);
    EXPECT_TRUE_RET((serialized_len - len_before_digest) > digestlen,
                    "corrupted digest length in message, aborting\n");
    buffer_t *serialized_digest =
        Buffer_deserialize(serialized_cipher + len_before_digest);

    EXPECT_TRUE_RET(
        (Buffer_get_size(serialized_digest) == digestlen),
        "serialized digest is not of the correct length, aborting\n");

    // Compute our digest

    // get our hmac key
    peacemakr_key_t *hmac_key = get_hmac_key(digest_algo);

    // Digest the message
    size_t computed_digest_out_size = 0;
    uint8_t *computed_raw_digest =
        peacemakr_hmac(digest_algo, hmac_key, serialized_cipher,
                       len_before_digest, &computed_digest_out_size);

    // Clean up
    PeacemakrKey_free(hmac_key);
    int memcmp_ret = CRYPTO_memcmp(computed_raw_digest,
                                   Buffer_get_bytes(serialized_digest, NULL),
                                   digestlen);
    free(computed_raw_digest);

    // Compare the HMACs
    if (memcmp_ret != 0) {
      PEACEMAKR_LOG("digests don't compare equal, aborting\n");
      return NULL;
    }
  }

  // version
  uint32_t version =
      ntohl(*((uint32_t *)(serialized_cipher + current_position)));
  current_position += sizeof(uint32_t);
  if (version > PEACEMAKR_CORE_CRYPTO_VERSION_MAX) {
    PEACEMAKR_ERROR("version greater than max supported");
    return NULL;
  }

  // encryption mode
  uint8_t encryption_mode = *(serialized_cipher + current_position);
  current_position += sizeof(uint8_t);

  // symm_cipher
  uint8_t symm_cipher = *(serialized_cipher + current_position);
  current_position += sizeof(uint8_t);

  // asymm_cipher
  uint8_t asymm_cipher = *(serialized_cipher + current_position);
  current_position += sizeof(uint8_t);

  cfg->mode = encryption_mode;
  cfg->symm_cipher = symm_cipher;
  cfg->asymm_cipher = asymm_cipher;
  cfg->digest_algorithm = digest_algo;

  // encrypted key
  buffer_t *encrypted_key =
      Buffer_deserialize(serialized_cipher + current_position);
  current_position += Buffer_get_serialized_size(encrypted_key);

  // iv
  buffer_t *iv = Buffer_deserialize(serialized_cipher + current_position);
  current_position += Buffer_get_serialized_size(iv);

  // tag
  buffer_t *tag = Buffer_deserialize(serialized_cipher + current_position);
  current_position += Buffer_get_serialized_size(tag);

  // aad
  buffer_t *aad = Buffer_deserialize(serialized_cipher + current_position);
  current_position += Buffer_get_serialized_size(aad);

  // ciphertext
  buffer_t *ciphertext =
      Buffer_deserialize(serialized_cipher + current_position);
  current_position += Buffer_get_serialized_size(ciphertext);

  // signature
  buffer_t *signature =
      Buffer_deserialize(serialized_cipher + current_position);

  ciphertext_blob_t *out = CiphertextBlob_new(
      *cfg, Buffer_get_size(iv), Buffer_get_size(tag), Buffer_get_size(aad),
      Buffer_get_size(ciphertext), Buffer_get_size(signature));

  CiphertextBlob_set_version(out, version);

  if (Buffer_get_size(encrypted_key) != 0) {
    Buffer_set_bytes(CiphertextBlob_mutable_encrypted_key(out),
                     Buffer_get_bytes(encrypted_key, NULL),
                     Buffer_get_size(encrypted_key));
  }

  if (iv != NULL) {
    CiphertextBlob_set_iv(out, Buffer_get_bytes(iv, NULL), Buffer_get_size(iv));
  }

  if (tag != NULL) {
    Buffer_set_bytes(CiphertextBlob_mutable_tag(out),
                     Buffer_get_bytes(tag, NULL), Buffer_get_size(tag));
  }

  if (aad != NULL) {
    Buffer_set_bytes(CiphertextBlob_mutable_aad(out),
                     Buffer_get_bytes(aad, NULL), Buffer_get_size(aad));
  }

  if (ciphertext != NULL) {
    Buffer_set_bytes(CiphertextBlob_mutable_ciphertext(out),
                     Buffer_get_bytes(ciphertext, NULL),
                     Buffer_get_size(ciphertext));
  }

  if (signature != NULL) {
    Buffer_set_bytes(CiphertextBlob_mutable_signature(out),
                     Buffer_get_bytes(signature, NULL),
                     Buffer_get_size(signature));
  }

  Buffer_free(encrypted_key);
  Buffer_free(iv);
  Buffer_free(tag);
  Buffer_free(aad);
  Buffer_free(ciphertext);
  Buffer_free(signature);

  return out;
}
