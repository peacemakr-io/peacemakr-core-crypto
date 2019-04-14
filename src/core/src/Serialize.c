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

static peacemakr_key_t *get_hmac_key() {
  peacemakr_key_t *hmac_key =
      peacemakr_key_new_bytes(CHACHA20_POLY1305, PEACEMAKR_MAGIC_KEY, 32);
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

uint8_t *peacemakr_serialize(message_digest_algorithm digest,
                             ciphertext_blob_t *cipher, size_t *b64_size) {
  EXPECT_TRUE_RET((cipher != NULL && b64_size != NULL),
                  "cipher or b64_size was null in call to serialize\n")
  EXPECT_TRUE_RET((digest != DIGEST_UNSPECIFIED),
                  "Must specify a message digest in serialize\n")

  if (ciphertext_blob_digest_algo(cipher) == DIGEST_UNSPECIFIED) {
    ciphertext_blob_set_digest_algo(cipher, digest);
  }

  size_t buffer_len = sizeof(uint32_t); // magic number
  buffer_len += sizeof(uint64_t);       // size of message up until digest
  buffer_len += sizeof(uint8_t);        // digest algo
  // version
  buffer_len += sizeof(uint32_t);
  // encryption mode, symm_cipher, asymm_cipher
  buffer_len += sizeof(uint8_t) * 3;

  const buffer_t *encrypted_key = ciphertext_blob_encrypted_key(cipher);
  buffer_len += buffer_get_serialized_size(encrypted_key);

  const buffer_t *iv = ciphertext_blob_iv(cipher);
  buffer_len += buffer_get_serialized_size(iv);

  const buffer_t *tag = ciphertext_blob_tag(cipher);
  buffer_len += buffer_get_serialized_size(tag);

  const buffer_t *aad = ciphertext_blob_aad(cipher);
  buffer_len += buffer_get_serialized_size(aad);

  const buffer_t *ciphertext = ciphertext_blob_ciphertext(cipher);
  buffer_len += buffer_get_serialized_size(ciphertext);

  const buffer_t *signature = ciphertext_blob_signature(cipher);
  buffer_len += buffer_get_serialized_size(signature);

  // We will digest the message and set it at the end
  buffer_len += sizeof(uint64_t);
  size_t digest_len = get_digest_len(ciphertext_blob_digest_algo(cipher));
  buffer_len += digest_len;

  uint8_t *buf = calloc(buffer_len, sizeof(uint8_t));
  size_t current_pos = 0;

  // magic
  uint32_t magic = htonl(_PEACEMAKR_MAGIC_);
  memcpy(buf, &magic, sizeof(uint32_t));
  current_pos += sizeof(uint32_t);

  // len until digest
  memset((buf + current_pos), 0, sizeof(uint64_t));
  current_pos += sizeof(uint64_t);

  // digest algo
  uint8_t digest_algo = ciphertext_blob_digest_algo(cipher);
  *(buf + current_pos) = digest_algo;
  current_pos += sizeof(uint8_t);

  // version
  uint32_t version = htonl(ciphertext_blob_version(cipher));
  memcpy(buf + current_pos, &version, sizeof(uint32_t));
  current_pos += sizeof(uint32_t);

  // encryption mode
  uint8_t encryption_mode = ciphertext_blob_encryption_mode(cipher);
  *(buf + current_pos) = encryption_mode;
  current_pos += sizeof(uint8_t);

  // symm cipher
  uint8_t symm_cipher = ciphertext_blob_symm_cipher(cipher);
  *(buf + current_pos) = symm_cipher;
  current_pos += sizeof(uint8_t);

  // asymm cipher
  uint8_t asymm_cipher = ciphertext_blob_asymm_cipher(cipher);
  *(buf + current_pos) = asymm_cipher;
  current_pos += sizeof(uint8_t);

  // encrypted key
  size_t ekey_len = buffer_serialize(encrypted_key, buf + current_pos);
  current_pos += ekey_len;

  // iv
  size_t ivlen = buffer_serialize(iv, buf + current_pos);
  current_pos += ivlen;

  // tag
  size_t taglen = buffer_serialize(tag, buf + current_pos);
  current_pos += taglen;

  // aad
  size_t aadlen = buffer_serialize(aad, buf + current_pos);
  current_pos += aadlen;

  // ciphertext
  size_t ciphertextlen = buffer_serialize(ciphertext, buf + current_pos);
  current_pos += ciphertextlen;

  // signature
  size_t signaturelen = buffer_serialize(signature, buf + current_pos);
  current_pos += signaturelen;

  // set the size of the buffer until the digest (at offset sizeof(uint32_t))
  uint64_t curr_pos = htonl(current_pos);
  memcpy(buf + sizeof(uint32_t), &curr_pos, sizeof(uint64_t));

  // get our hmac key
  peacemakr_key_t *hmac_key = get_hmac_key();

  // Digest the message
  size_t digest_out_size = 0;
  uint8_t *raw_digest =
      peacemakr_hmac(ciphertext_blob_digest_algo(cipher), hmac_key, buf,
                     current_pos, &digest_out_size);

  // Make sure we didn't do a stupid
  EXPECT_TRUE_CLEANUP_RET(digest_out_size == digest_len, free(buf),
                          "Computed HMAC was of the incorrect size\n")

  // Store it
  buffer_t *message_digest = buffer_new(digest_len);
  buffer_set_bytes(message_digest, raw_digest, digest_out_size);

  // Clean up
  free(raw_digest);
  peacemakr_key_free(hmac_key);

  // Append the digest
  size_t digestlen = buffer_serialize(message_digest, buf + current_pos);
  current_pos += digestlen;

  // Clean up the buffer
  buffer_free(message_digest);

  // Clean up the ciphertext blob
  ciphertext_blob_free(cipher);
  cipher = NULL;

  // Return the b64 encoded version
  uint8_t *b64_buf = (uint8_t *)b64_encode(buf, current_pos, b64_size);

  // Clean up the workspace
  free(buf);

  return b64_buf;
}

ciphertext_blob_t *peacemakr_deserialize(const uint8_t *b64_serialized_cipher,
                                         size_t b64_serialized_len,
                                         crypto_config_t *cfg) {

  // Make sure the input is valid
  EXPECT_TRUE_RET((b64_serialized_cipher != NULL),
                  "b64 serialized cipher was NULL or invalid\n")
  EXPECT_TRUE_RET((b64_serialized_len != 0), "b64_serialized_len was 0\n")
  EXPECT_NOT_NULL_RET(
      cfg, "need to store the deserialized configuration somewhere\n")

  // If we are a null-terminated string, then remove that from the size.
  // The b64 decode expects that the length passed in does NOT include the
  // null terminator.
  b64_serialized_len -= (b64_serialized_cipher[b64_serialized_len - 1] == '\0');

  // We're decoding a b64 message so get the serialized length (rounded up)
  size_t serialized_len = (b64_serialized_len + 3) / 4 * 3;
  EXPECT_TRUE_RET((serialized_len < b64_serialized_len),
                  "Unexpected condition in computing b64 decoded length\n")
  uint8_t *serialized_cipher = calloc(serialized_len, sizeof(uint8_t));
  EXPECT_NOT_NULL_RET(serialized_cipher, "failed to allocate serialized_cipher")

  // Don't free the b64 cipher because we don't own that memory
  bool decoded =
      b64_decode((const char *)b64_serialized_cipher, b64_serialized_len,
                 serialized_cipher, serialized_len);
  EXPECT_TRUE_CLEANUP_RET(decoded, free(serialized_cipher),
                          "b64 decode failed\n")

  size_t current_position = 0;

  // magic
  uint32_t magic = ntohl(*(uint32_t *)serialized_cipher);
  EXPECT_TRUE_CLEANUP_RET((magic == _PEACEMAKR_MAGIC_), free(serialized_cipher),
                          "magic number corrupted/missing, aborting\n")
  current_position += sizeof(uint32_t);

  // len until digest
  uint64_t len_before_digest =
      ntohl(*(uint64_t *)(serialized_cipher + current_position));
  current_position += sizeof(uint64_t);

  // Something is bad
  EXPECT_TRUE_CLEANUP_RET((len_before_digest < b64_serialized_len),
                          free(serialized_cipher),
                          "corrupted length in message, aborting\n")

  // digest algo
  uint8_t digest_algo = *(serialized_cipher + current_position);
  current_position += sizeof(uint8_t);

  { // Check that the message digests are equal
    const EVP_MD *digest_algorithm = parse_digest(digest_algo);
    EXPECT_NOT_NULL_CLEANUP_RET(digest_algorithm, free(serialized_cipher),
                                "corrupted digest algorithm, aborting\n")

    size_t digestlen = get_digest_len(digest_algo);
    EXPECT_TRUE_CLEANUP_RET((b64_serialized_len - len_before_digest) >
                                digestlen,
                            free(serialized_cipher),
                            "corrupted digest length in message, aborting\n")
    buffer_t *serialized_digest =
        buffer_deserialize(serialized_cipher + len_before_digest);

    EXPECT_TRUE_CLEANUP_RET(
        (buffer_get_size(serialized_digest) == digestlen),
        free(serialized_cipher),
        "serialized digest is not of the correct length, aborting\n")

    // Compute our digest

    // get our hmac key
    peacemakr_key_t *hmac_key = get_hmac_key();

    // Digest the message
    size_t computed_digest_out_size = 0;
    uint8_t *computed_raw_digest =
        peacemakr_hmac(digest_algo, hmac_key, serialized_cipher,
                       len_before_digest, &computed_digest_out_size);

    // Clean up
    peacemakr_key_free(hmac_key);
    int memcmp_ret =
        CRYPTO_memcmp(computed_raw_digest,
                      buffer_get_bytes(serialized_digest, NULL), digestlen);

    free(computed_raw_digest);
    buffer_free(serialized_digest);

    // Compare the HMACs
    EXPECT_TRUE_CLEANUP_RET((memcmp_ret == 0), free(serialized_cipher),
                            "digests don't compare equal, aborting\n")
  }

  // version
  uint32_t version =
      ntohl(*((uint32_t *)(serialized_cipher + current_position)));
  current_position += sizeof(uint32_t);
  EXPECT_TRUE_CLEANUP_RET((version <= PEACEMAKR_CORE_CRYPTO_VERSION_MAX),
                          free(serialized_cipher),
                          "version greater than max supported\n")

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
      buffer_deserialize(serialized_cipher + current_position);
  current_position += buffer_get_serialized_size(encrypted_key);

  // iv
  buffer_t *iv = buffer_deserialize(serialized_cipher + current_position);
  current_position += buffer_get_serialized_size(iv);

  // tag
  buffer_t *tag = buffer_deserialize(serialized_cipher + current_position);
  current_position += buffer_get_serialized_size(tag);

  // aad
  buffer_t *aad = buffer_deserialize(serialized_cipher + current_position);
  current_position += buffer_get_serialized_size(aad);

  // ciphertext
  buffer_t *ciphertext =
      buffer_deserialize(serialized_cipher + current_position);
  current_position += buffer_get_serialized_size(ciphertext);

  // signature
  buffer_t *signature =
      buffer_deserialize(serialized_cipher + current_position);

  // Ciphertext blob takes ownership of the buffers, so don't free the buffers
  // at the end of the function
  ciphertext_blob_t *out = ciphertext_blob_from_buffers(
      *cfg, encrypted_key, iv, tag, aad, ciphertext, signature);

  ciphertext_blob_set_version(out, version);

  free(serialized_cipher);

  return out;
}
