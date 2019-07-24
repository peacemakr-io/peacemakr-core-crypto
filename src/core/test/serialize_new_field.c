//
// Created by Aman LaChapelle on 2019-06-06.
//
// peacemakr_core_crypto
// Copyright (c) 2019 Aman LaChapelle
// Full license at peacemakr_core_crypto/LICENSE.txt
//

#include <assert.h>
#include <memory.h>

#include "../include/peacemakr/crypto.h"

#include "../src/Buffer.h"
#include "../src/CiphertextBlob.h"
#include "../src/EVPHelper.h"
#include "../src/Endian.h"
#include "../src/Logging.h"
#include "../src/b64.h"

#include "utils/helper.h"

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
static const size_t some_new_field = 9;

static uint8_t *serialize_headers(const ciphertext_blob_t *blob,
                                  size_t *final_len) {
  assert(final_len != NULL);

  const uint32_t config_size = 4;
  const size_t num_table_entries = 10;
  const uint32_t offset_table_size = num_table_entries * sizeof(uint32_t);
  const uint32_t offset_table_end = sizeof(uint32_t) + offset_table_size;

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
  buffer_len += 60; // some new field

  // HMAC's length is determined by the crypto config of the message
  buffer_len += get_digest_len(ciphertext_blob_digest_algo(blob));

  *final_len = buffer_len;

  uint8_t *out = calloc(buffer_len, sizeof(uint8_t));

  const uint32_t iv_offset =
      buffer_get_serialized_size(ciphertext_blob_iv(blob));
  const uint32_t tag_offset =
      buffer_get_serialized_size(ciphertext_blob_tag(blob));

  // Set the version
  ((uint32_t *)out)[0] = ciphertext_blob_version(blob);

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

  // new field offset
  ((uint32_t *)out)[some_new_field] = ENDIAN_CHECK(
      offset_table_end + config_size + iv_offset + tag_offset +
      /* sizeof([4]) */
      buffer_get_serialized_size(ciphertext_blob_encrypted_key(blob)) +
      /* sizeof([7]) */ buffer_get_serialized_size(ciphertext_blob_aad(blob)) +
      /* sizeof([8]) */
      buffer_get_serialized_size(ciphertext_blob_ciphertext(blob)) +
      /* sizeof([9]) */
      buffer_get_serialized_size(ciphertext_blob_signature(blob)));

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

static uint32_t get_new_field_offset(const uint8_t *buf,
                                     const size_t buf_size) {
  uint32_t out = ENDIAN_CHECK(((uint32_t *)buf)[some_new_field]);
  if (out > buf_size) {
    PEACEMAKR_ERROR("Corrupted message, could not get the signature offset\n");
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

uint8_t *test_serialize(ciphertext_blob_t *cipher, size_t *outlen) {
  if (ciphertext_blob_digest_algo(cipher) == DIGEST_UNSPECIFIED) {
    ciphertext_blob_set_digest_algo(cipher, SHA_256);
  }

  uint8_t *raw_out = serialize_headers(cipher, outlen);
  // Serialize new field into the message
  uint32_t new_field_offset = get_new_field_offset(raw_out, *outlen);

  const char *new_field_data =
      "Hello, I'm a new field that older versions should ignore!";

  memcpy(raw_out + new_field_offset, new_field_data, 58);

  serialize_crypto_config(raw_out, *outlen, cipher);
  serialize_encrypted_key(raw_out, *outlen, cipher);
  serialize_iv(raw_out, *outlen, cipher);
  serialize_tag(raw_out, *outlen, cipher);
  serialize_aad(raw_out, *outlen, cipher);
  serialize_ciphertext(raw_out, *outlen, cipher);
  serialize_signature(raw_out, *outlen, cipher);
  serialize_hmac(raw_out, *outlen, cipher);

  // Return the b64 encoded version
  uint8_t *b64_buf = b64_encode(raw_out, *outlen, outlen);

  // Clean up the workspace
  free(raw_out);

  return b64_buf;
}

ciphertext_blob_t *test_old_version_deserialize(const uint8_t *buf,
                                                const size_t buflen,
                                                const ciphertext_blob_t *blob) {
  crypto_config_t cfg;
  // Using the library version of deserialize - doesn't have the new field
  ciphertext_blob_t *newblob = peacemakr_deserialize(buf, buflen, &cfg);
  if (ciphertext_blob_digest_algo(newblob) == DIGEST_UNSPECIFIED) {
    ciphertext_blob_set_digest_algo(newblob, SHA_256);
  }

  bool equal = ciphertext_blob_compare(blob, newblob);
  assert(equal);
  return newblob;
}

const char *message = "Hello, world! I'm testing encryption from C!"; // 37 + 1
const char *message_aad = "And I'm AAD";                              // 11 + 1

int main() {
  plaintext_t plaintext_in = {.data = (const unsigned char *)message,
                              .data_len = strlen(message) + 1,
                              .aad = (const unsigned char *)message_aad,
                              .aad_len = strlen(message_aad) + 1};

  plaintext_t plaintext_out;

  random_device_t rand = get_default_random_device();

  peacemakr_key_t *key = peacemakr_key_new_symmetric(CHACHA20_POLY1305, &rand);

  ciphertext_blob_t *ciphertext = peacemakr_encrypt(key, &plaintext_in, &rand);
  assert(ciphertext != NULL);

  size_t outsize = 0;
  uint8_t *serialized = test_serialize(ciphertext, &outsize);
  assert(serialized != NULL);

  ciphertext_blob_t *deserialized =
      test_old_version_deserialize(serialized, outsize, ciphertext);
  decrypt_code success = peacemakr_decrypt(key, deserialized, &plaintext_out);

  assert(success == DECRYPT_SUCCESS);
  free(serialized);

  assert(strncmp((const char *)plaintext_out.data,
                 (const char *)plaintext_in.data, plaintext_in.data_len) == 0);
  free((void *)plaintext_out.data);
  assert(strncmp((const char *)plaintext_out.aad,
                 (const char *)plaintext_in.aad, plaintext_in.data_len) == 0);
  free((void *)plaintext_out.aad);

  ciphertext_blob_free(ciphertext);

  peacemakr_key_free(key);
}
