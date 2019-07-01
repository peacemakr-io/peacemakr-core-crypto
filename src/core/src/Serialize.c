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
#include "Endian.h"
#include "Logging.h"
#include "b64.h"

#include <arpa/inet.h>
#include <memory.h>

/**
 * @file
 * Message Serialization Format 0x1
 *
 * All multi-byte fields are serialized in LE format, and each
 * field is prefixed by its length.
 *
 * @code
 * --------------------------------------------
 * (header) Version number (32 bits)
 * --------------------------------------------
 * (header) Offset table:
 *
 * - Number of offsets in table
 * - Offset to data start
 * - Offset to [4]
 * - Offset to [5]
 * - Offset to [6]
 * ...
 * - Offset to [10]
 *
 * (entry) - offset in bytes (length_t)
 * ---------------
 *     [0] - 0 (omitted)
 *     [1] - 1 (omitted)
 *     [2] - 2 (omitted)
 *     [3] - 3 (omitted)
 *     [4] - 4 (omitted)
 *     [5] - 28 + sizeof([4])
 *     [6] - 44 + sizeof([4])
 *     [7] - 60 + sizeof([4])
 *     [8] - 60 + sizeof([4]) + sizeof([7])
 *     [9] - 60 + sizeof([4]) + sizeof([7]) + sizeof([8])
 *    [10] - 60 + sizeof([4]) + sizeof([7]) + sizeof([8]) + sizeof([9])
 *
 * --------------------------------------------
 * [0] Encryption Mode (8 bits)
 * --------------------------------------------
 * [1] Symmetric Cipher Algorithm (8 bits)
 * --------------------------------------------
 * [2] Asymmetric Cipher Algorithm (8 bits)
 * --------------------------------------------
 * [3] Digest Algorithm (8 bits)
 * --------------------------------------------
 * [4] Encrypted key ({128, 192, 256} bits)
 * --------------------------------------------
 * [5] IV (128 bits)
 * --------------------------------------------
 * [6] Tag (128 bits)
 * --------------------------------------------
 * [7] AAD
 * --------------------------------------------
 * [8] Ciphertext
 * --------------------------------------------
 * [9] Signature
 * --------------------------------------------
 * [10] Message HMAC ({224, 256, 384, 512} bits)
 * --------------------------------------------
 * @endcode
 *
 *
 * In order to add a new field to the message format:
 * -# Update the number of table entries in serialize_headers
 * -# Add the index of your offset to the static data below
 * -# Add the offset of your entry to the table before the hmac offset at the
 *     end but after the signature field
 * -# Add a getter for your offset
 * -# Add a serializer and deserializer for your field to use in
 *     peacemakr_serialize/peacemakr_deserialize
 */

//! HMAC-SHA512 needs a 64 byte key. Shorter HMAC versions will truncate.
static const uint8_t PEACEMAKR_MAGIC_KEY[64] =
    "7d3rAfIHtCbYLm1OY6IRjvoBdqw2QdyvPIECF4Aczs2LgiShn8CeO8c21Q+GMuGf";

static peacemakr_key_t *get_hmac_key() {
  peacemakr_key_t *hmac_key =
      peacemakr_key_new_bytes(CHACHA20_POLY1305, PEACEMAKR_MAGIC_KEY, 64);
  return hmac_key;
}

static const size_t table_entries_index = 1;
static const size_t data_start_index = 2;
static const size_t encrypted_key_offset_index = 3;
static const size_t iv_offset_index = 4;
static const size_t tag_offset_index = 5;
static const size_t aad_offset_index = 6;
static const size_t ciphertext_offset_index = 7;
static const size_t signature_offset_index = 8;

static uint8_t *serialize_headers(const ciphertext_blob_t *blob,
                                  size_t *final_len) {
  EXPECT_NOT_NULL_RET(final_len,
                      "Cannot store an output size in a NULL pointer\n")

  const length_t config_size = 4;
  const size_t num_table_entries = 9;
  const length_t offset_table_size = num_table_entries * sizeof(length_t);
  const length_t offset_table_end = sizeof(length_t) + offset_table_size;

  size_t buffer_len = sizeof(uint32_t); // version number
  buffer_len += offset_table_size;      // Offset table
  buffer_len += 4 * sizeof(uint8_t);    // crypto config of the message
  buffer_len += buffer_get_serialized_size(
      ciphertext_blob_encrypted_key(blob)); // encrypted key
  buffer_len += buffer_get_serialized_size(ciphertext_blob_iv(blob));  // IV
  buffer_len += buffer_get_serialized_size(ciphertext_blob_tag(blob)); // Tag
  buffer_len += buffer_get_serialized_size(ciphertext_blob_aad(blob)); // AAD
  buffer_len += buffer_get_serialized_size(
      ciphertext_blob_ciphertext(blob)); // Ciphertext
  buffer_len +=
      buffer_get_serialized_size(ciphertext_blob_signature(blob)); // Signature

  // HMAC's length is determined by the crypto config of the message
  buffer_len += get_digest_len(ciphertext_blob_digest_algo(blob));

  *final_len = buffer_len;

  uint8_t *out = calloc(buffer_len, sizeof(uint8_t));

  const length_t iv_offset =
      buffer_get_serialized_size(ciphertext_blob_iv(blob));
  const length_t tag_offset =
      buffer_get_serialized_size(ciphertext_blob_tag(blob));

  // Set the version
  ((length_t *)out)[0] = ciphertext_blob_version(blob);

  // Set the header offset table

  // Number of offsets in table
  ((length_t *)out)[table_entries_index] = ENDIAN_CHECK(num_table_entries);

  // Data start offset
  ((length_t *)out)[data_start_index] = ENDIAN_CHECK(offset_table_end);

  // Config end offset (encrypted key offset)
  ((length_t *)out)[encrypted_key_offset_index] =
      ENDIAN_CHECK(offset_table_end + config_size);

  // IV offset
  ((length_t *)out)[iv_offset_index] = ENDIAN_CHECK(
      offset_table_end + config_size +
      /* sizeof([4]) */
      buffer_get_serialized_size(ciphertext_blob_encrypted_key(blob)));

  // Tag offset
  ((length_t *)out)[tag_offset_index] = ENDIAN_CHECK(
      offset_table_end + config_size + iv_offset +
      /* sizeof([4]) */
      buffer_get_serialized_size(ciphertext_blob_encrypted_key(blob)));

  // AAD offset
  ((length_t *)out)[aad_offset_index] = ENDIAN_CHECK(
      offset_table_end + config_size + iv_offset + tag_offset +
      /* sizeof([4]) */
      buffer_get_serialized_size(ciphertext_blob_encrypted_key(blob)));

  // Ciphertext offset
  ((length_t *)out)[ciphertext_offset_index] = ENDIAN_CHECK(
      offset_table_end + config_size + iv_offset + tag_offset +
      /* sizeof([4]) */
      buffer_get_serialized_size(ciphertext_blob_encrypted_key(blob)) +
      /* sizeof([7]) */ buffer_get_serialized_size(ciphertext_blob_aad(blob)));

  // Signature offset
  ((length_t *)out)[signature_offset_index] = ENDIAN_CHECK(
      offset_table_end + config_size + iv_offset + tag_offset +
      /* sizeof([4]) */
      buffer_get_serialized_size(ciphertext_blob_encrypted_key(blob)) +
      /* sizeof([7]) */ buffer_get_serialized_size(ciphertext_blob_aad(blob)) +
      /* sizeof([8]) */
      buffer_get_serialized_size(ciphertext_blob_ciphertext(blob)));

  // HMAC offset
  ((length_t *)out)[num_table_entries] = ENDIAN_CHECK(
      offset_table_end + config_size + iv_offset + tag_offset +
      /* sizeof([4]) */
      buffer_get_serialized_size(ciphertext_blob_encrypted_key(blob)) +
      /* sizeof([7]) */ buffer_get_serialized_size(ciphertext_blob_aad(blob)) +
      /* sizeof([8]) */
      buffer_get_serialized_size(ciphertext_blob_ciphertext(blob)) +
      /* sizeof([9]) */
      buffer_get_serialized_size(ciphertext_blob_signature(blob)));

  return out;
}

// Just returns the version, the rest of the offset table is used for the
// individual functions
static uint32_t deserialize_headers(const uint8_t *buf, const size_t buf_size) {
  uint32_t out = ENDIAN_CHECK(((uint32_t *)buf)[0]);
  if (out > buf_size) {
    PEACEMAKR_ERROR("Corrupted message, could not get the offset of header\n");
    return UINT32_MAX;
  }
  return out;
}

static length_t get_num_offsets(const uint8_t *buf, const size_t buf_size) {
  length_t out = ENDIAN_CHECK(((length_t *)buf)[table_entries_index]);
  if (out > buf_size) {
    PEACEMAKR_ERROR("Corrupted message, could not get the number of offsets\n");
    return UINT32_MAX;
  }

  return out;
}

static length_t get_data_start_offset(const uint8_t *buf,
                                      const size_t buf_size) {
  length_t out = ENDIAN_CHECK(((length_t *)buf)[data_start_index]);
  if (out > buf_size) {
    PEACEMAKR_ERROR("Corrupted message, could not get the data start offset\n");
    return UINT32_MAX;
  }

  return out;
}

static length_t get_encrypted_key_offset(const uint8_t *buf,
                                         const size_t buf_size) {
  length_t out = ENDIAN_CHECK(((length_t *)buf)[encrypted_key_offset_index]);
  if (out > buf_size) {
    PEACEMAKR_ERROR(
        "Corrupted message, could not get the encrypted key offset\n");
    return UINT32_MAX;
  }
  return out;
}

static length_t get_iv_offset(const uint8_t *buf, const size_t buf_size) {
  length_t out = ENDIAN_CHECK(((length_t *)buf)[iv_offset_index]);
  if (out > buf_size) {
    PEACEMAKR_ERROR("Corrupted message, could not get the iv offset\n");
    return UINT32_MAX;
  }
  return out;
}

static length_t get_tag_offset(const uint8_t *buf, const size_t buf_size) {
  length_t out = ENDIAN_CHECK(((length_t *)buf)[tag_offset_index]);
  if (out > buf_size) {
    PEACEMAKR_ERROR("Corrupted message, could not get the tag offset\n");
    return UINT32_MAX;
  }
  return out;
}

static length_t get_aad_offset(const uint8_t *buf, const size_t buf_size) {
  length_t out = ENDIAN_CHECK(((length_t *)buf)[aad_offset_index]);
  if (out > buf_size) {
    PEACEMAKR_ERROR("Corrupted message, could not get the aad offset\n");
    return UINT32_MAX;
  }
  return out;
}

static length_t get_ciphertext_offset(const uint8_t *buf,
                                      const size_t buf_size) {
  length_t out = ENDIAN_CHECK(((length_t *)buf)[ciphertext_offset_index]);
  if (out > buf_size) {
    PEACEMAKR_ERROR("Corrupted message, could not get the ciphertext offset\n");
    return UINT32_MAX;
  }
  return out;
}

static length_t get_signature_offset(const uint8_t *buf,
                                     const size_t buf_size) {
  length_t out = ENDIAN_CHECK(((length_t *)buf)[signature_offset_index]);
  if (out > buf_size) {
    PEACEMAKR_ERROR("Corrupted message, could not get the signature offset\n");
    return UINT32_MAX;
  }
  return out;
}

static length_t get_hmac_offset(const uint8_t *buf, const size_t buf_size) {
  length_t num_offsets = get_num_offsets(buf, buf_size);
  if (num_offsets == UINT32_MAX) {
    return UINT32_MAX;
  }

  length_t out = ENDIAN_CHECK(((length_t *)buf)[num_offsets]);
  if (out > buf_size) {
    PEACEMAKR_ERROR("Corrupted message, could not get the hmac offset\n");
    return UINT32_MAX;
  }

  return out;
}

static void serialize_crypto_config(uint8_t *buf, const size_t buf_size,
                                    const ciphertext_blob_t *blob) {
  const length_t data_start_offset = get_data_start_offset(buf, buf_size);
  if (data_start_offset == UINT32_MAX) {
    return;
  }

  uint8_t *buf_start = buf + data_start_offset;
  // Set up crypto config
  buf_start[0] = ciphertext_blob_encryption_mode(blob);
  buf_start[1] = ciphertext_blob_symm_cipher(blob);
  buf_start[2] = ciphertext_blob_asymm_cipher(blob);
  buf_start[3] = ciphertext_blob_digest_algo(blob);
}

static crypto_config_t deserialize_crypto_config(const uint8_t *buf,
                                                 const size_t buf_size) {
  const length_t data_start_offset = get_data_start_offset(buf, buf_size);
  if (data_start_offset == UINT32_MAX) {
    crypto_config_t out;
    memset(&out, 0, sizeof(crypto_config_t));
    return out;
  }

  const uint8_t *buf_start = buf + data_start_offset;

  crypto_config_t out = {.mode = buf_start[0],
                         .symm_cipher = buf_start[1],
                         .asymm_cipher = buf_start[2],
                         .digest_algorithm = buf_start[3]};

  return out;
}

static void serialize_encrypted_key(uint8_t *buf, const size_t buf_size,
                                    const ciphertext_blob_t *blob) {
  const length_t encrypted_key_offset = get_encrypted_key_offset(buf, buf_size);
  if (encrypted_key_offset == UINT32_MAX) {
    return;
  }

  uint8_t *buf_start = buf + encrypted_key_offset;

  const buffer_t *enc_key = ciphertext_blob_encrypted_key(blob);
  (void)buffer_serialize(enc_key, buf_start);
}

static buffer_t *deserialize_encrypted_key(const uint8_t *buf,
                                           const size_t buf_size) {
  const length_t encrypted_key_offset = get_encrypted_key_offset(buf, buf_size);
  if (encrypted_key_offset == UINT32_MAX) {
    return NULL;
  }

  const uint8_t *buf_start = buf + encrypted_key_offset;
  return buffer_deserialize(buf_start);
}

static void serialize_iv(uint8_t *buf, const size_t buf_size,
                         const ciphertext_blob_t *blob) {
  const length_t iv_offset = get_iv_offset(buf, buf_size);
  if (iv_offset == UINT32_MAX) {
    return;
  }

  uint8_t *buf_start = buf + iv_offset;

  const buffer_t *iv = ciphertext_blob_iv(blob);
  (void)buffer_serialize(iv, buf_start);
}

static buffer_t *deserialize_iv(const uint8_t *buf, const size_t buf_size) {
  const length_t iv_offset = get_iv_offset(buf, buf_size);
  if (iv_offset == UINT32_MAX) {
    return NULL;
  }

  const uint8_t *buf_start = buf + iv_offset;
  return buffer_deserialize(buf_start);
}

static void serialize_tag(uint8_t *buf, const size_t buf_size,
                          const ciphertext_blob_t *blob) {
  const length_t tag_offset = get_tag_offset(buf, buf_size);
  if (tag_offset == UINT32_MAX) {
    return;
  }

  uint8_t *buf_start = buf + tag_offset;

  const buffer_t *tag = ciphertext_blob_tag(blob);
  (void)buffer_serialize(tag, buf_start);
}

static buffer_t *deserialize_tag(const uint8_t *buf, const size_t buf_size) {
  const length_t tag_offset = get_tag_offset(buf, buf_size);
  if (tag_offset == UINT32_MAX) {
    return NULL;
  }

  const uint8_t *buf_start = buf + tag_offset;
  return buffer_deserialize(buf_start);
}

static void serialize_aad(uint8_t *buf, const size_t buf_size,
                          const ciphertext_blob_t *blob) {
  const length_t aad_offset = get_aad_offset(buf, buf_size);
  if (aad_offset == UINT32_MAX) {
    return;
  }

  uint8_t *buf_start = buf + aad_offset;

  const buffer_t *aad = ciphertext_blob_aad(blob);
  (void)buffer_serialize(aad, buf_start);
}

static buffer_t *deserialize_aad(const uint8_t *buf, const size_t buf_size) {
  const length_t aad_offset = get_aad_offset(buf, buf_size);
  if (aad_offset == UINT32_MAX) {
    return NULL;
  }

  const uint8_t *buf_start = buf + aad_offset;
  return buffer_deserialize(buf_start);
}

static void serialize_ciphertext(uint8_t *buf, const size_t buf_size,
                                 const ciphertext_blob_t *blob) {
  const length_t ciphertext_offset = get_ciphertext_offset(buf, buf_size);
  if (ciphertext_offset == UINT32_MAX) {
    return;
  }

  uint8_t *buf_start = buf + ciphertext_offset;

  const buffer_t *ciphertext = ciphertext_blob_ciphertext(blob);
  (void)buffer_serialize(ciphertext, buf_start);
}

static buffer_t *deserialize_ciphertext(const uint8_t *buf,
                                        const size_t buf_size) {
  const length_t ciphertext_offset = get_ciphertext_offset(buf, buf_size);
  if (ciphertext_offset == UINT32_MAX) {
    return NULL;
  }

  const uint8_t *buf_start = buf + ciphertext_offset;
  return buffer_deserialize(buf_start);
}

static void serialize_signature(uint8_t *buf, const size_t buf_size,
                                const ciphertext_blob_t *blob) {
  const length_t signature_offset = get_signature_offset(buf, buf_size);
  if (signature_offset == UINT32_MAX) {
    return;
  }

  uint8_t *buf_start = buf + signature_offset;

  const buffer_t *signature = ciphertext_blob_signature(blob);
  (void)buffer_serialize(signature, buf_start);
}

static buffer_t *deserialize_signature(const uint8_t *buf,
                                       const size_t buf_size) {
  const length_t signature_offset = get_signature_offset(buf, buf_size);
  if (signature_offset == UINT32_MAX) {
    return NULL;
  }

  const uint8_t *buf_start = buf + signature_offset;
  return buffer_deserialize(buf_start);
}

static void serialize_hmac(uint8_t *buf, const size_t buf_size,
                           const ciphertext_blob_t *blob) {
  const length_t hmac_offset = get_hmac_offset(buf, buf_size);
  if (hmac_offset == UINT32_MAX) {
    return;
  }

  uint8_t *buf_start = buf + hmac_offset;

  message_digest_algorithm blob_digest = ciphertext_blob_digest_algo(blob);
  peacemakr_key_t *hmac_key = get_hmac_key();

  // Digest the message
  size_t digest_out_size = 0;
  uint8_t *raw_digest =
      peacemakr_hmac(blob_digest, hmac_key, buf, get_hmac_offset(buf, buf_size),
                     &digest_out_size);

  EXPECT_TRUE_CLEANUP_RET_NONE(digest_out_size == get_digest_len(blob_digest),
                               free(raw_digest),
                               "Computed HMAC was of the incorrect size\n")

  // HMAC length determined by the config of the message blob.
  memcpy(buf_start, raw_digest, digest_out_size);

  free(raw_digest);
  peacemakr_key_free(hmac_key);
}

static bool deserialize_hmac(const uint8_t *buf, const size_t buf_size) {
  const length_t hmac_offset = get_hmac_offset(buf, buf_size);
  if (hmac_offset == UINT32_MAX) {
    return false;
  }

  const uint8_t *buf_start = buf + hmac_offset;

  crypto_config_t message_config = deserialize_crypto_config(buf, buf_size);

  // This could be 0
  size_t field_size = get_digest_len(message_config.digest_algorithm);

  buffer_t *out = buffer_new(field_size);
  buffer_set_bytes(out, buf_start, field_size);

  { // Check that the message digests are equal
    const EVP_MD *digest_algorithm =
        parse_digest(message_config.digest_algorithm);
    if (digest_algorithm == NULL) {
      buffer_free(out);
      PEACEMAKR_ERROR("corrupted digest algorithm, aborting\n");
      return false;
    }

    size_t digestlen = get_digest_len(message_config.digest_algorithm);

    if (field_size != digestlen) {
      buffer_free(out);
      PEACEMAKR_ERROR(
          "serialized digest is not of the correct length, aborting\n");
      return false;
    }

    // Compute our digest

    // get our hmac key
    peacemakr_key_t *hmac_key = get_hmac_key();

    // Digest the message
    size_t computed_digest_out_size = 0;
    uint8_t *computed_raw_digest = peacemakr_hmac(
        message_config.digest_algorithm, hmac_key, buf,
        get_hmac_offset(buf, buf_size), &computed_digest_out_size);

    // Clean up
    peacemakr_key_free(hmac_key);
    int memcmp_ret = CRYPTO_memcmp(computed_raw_digest,
                                   buffer_get_bytes(out, NULL), digestlen);

    free(computed_raw_digest);
    buffer_free(out);

    // Compare the HMACs
    if (memcmp_ret != 0) {
      PEACEMAKR_ERROR("digests don't compare equal, aborting\n");
      return false;
    }
  }

  return true;
}

uint8_t *peacemakr_serialize(message_digest_algorithm digest,
                             ciphertext_blob_t *cipher, size_t *b64_size) {
  EXPECT_TRUE_RET((cipher != NULL && b64_size != NULL),
                  "cipher or b64_size was null in call to serialize\n")
  EXPECT_TRUE_RET((digest != DIGEST_UNSPECIFIED),
                  "Must specify a message digest in serialize\n")

  if (ciphertext_blob_digest_algo(cipher) == DIGEST_UNSPECIFIED) {
    ciphertext_blob_set_digest_algo(cipher, digest);
  }

  size_t outlen = 0;
  uint8_t *raw_out = serialize_headers(cipher, &outlen);
  serialize_crypto_config(raw_out, outlen, cipher);
  serialize_encrypted_key(raw_out, outlen, cipher);
  serialize_iv(raw_out, outlen, cipher);
  serialize_tag(raw_out, outlen, cipher);
  serialize_aad(raw_out, outlen, cipher);
  serialize_ciphertext(raw_out, outlen, cipher);
  serialize_signature(raw_out, outlen, cipher);
  serialize_hmac(raw_out, outlen, cipher);

  // Clean up the ciphertext blob
  ciphertext_blob_free(cipher);
  cipher = NULL;

  // Return the b64 encoded version
  uint8_t *b64_buf = b64_encode(raw_out, outlen, b64_size);

  // Clean up the workspace
  free(raw_out);

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

  // Don't free the b64 cipher because we don't own that memory
  size_t serialized_len = 0;
  uint8_t *serialized_cipher =
      b64_decode(b64_serialized_cipher, b64_serialized_len, &serialized_len);
  EXPECT_NOT_NULL_RET(serialized_cipher, "failed to decode b64 object\n")

  uint32_t version = deserialize_headers(serialized_cipher, serialized_len);
  EXPECT_TRUE_CLEANUP_RET((version <= PEACEMAKR_CORE_CRYPTO_VERSION_MAX),
                          free(serialized_cipher),
                          "version greater than max supported\n")

  bool valid_message = deserialize_hmac(serialized_cipher, serialized_len);
  EXPECT_TRUE_CLEANUP_RET(valid_message, free(serialized_cipher),
                          "HMAC verification failed, aborting\n")

  *cfg = deserialize_crypto_config(serialized_cipher, serialized_len);
  buffer_t *encrypted_key =
      deserialize_encrypted_key(serialized_cipher, serialized_len);
  buffer_t *iv = deserialize_iv(serialized_cipher, serialized_len);
  buffer_t *tag = deserialize_tag(serialized_cipher, serialized_len);
  buffer_t *aad = deserialize_aad(serialized_cipher, serialized_len);
  buffer_t *ciphertext =
      deserialize_ciphertext(serialized_cipher, serialized_len);
  buffer_t *signature =
      deserialize_signature(serialized_cipher, serialized_len);

  ciphertext_blob_t *out = ciphertext_blob_from_buffers(
      *cfg, encrypted_key, iv, tag, aad, ciphertext, signature);

  ciphertext_blob_set_version(out, version);

  free(serialized_cipher);

  return out;
}
