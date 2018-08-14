//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include <Buffer.h>
#include <crypto.h>

#include "CiphertextBlob.h"
#include "EVPHelper.h"
#include <Logging.h>
#include <memory.h>
#include <openssl/evp.h>

#define _PEACEMAKR_MAGIC_ (uint32_t)0x1054

// base64 encode - https://gist.github.com/barrysteyn/7308212

static void digest_message(const unsigned char *message, size_t message_len,
                           const EVP_MD *digest_algo, buffer_t *digest) {
  EVP_MD_CTX *mdctx;

  if ((mdctx = EVP_MD_CTX_create()) == NULL) {
    PEACEMAKR_ERROR("mdctx_create failed");
    return;
  }

  if (1 != EVP_DigestInit_ex(mdctx, digest_algo, NULL)) {
    PEACEMAKR_ERROR("digestinit_ex failed");
    return;
  }

  if (1 != EVP_DigestUpdate(mdctx, message, message_len)) {
    PEACEMAKR_ERROR("digestupdate failed");
    return;
  }

  size_t digest_len = Buffer_get_size(digest);
  unsigned char digest_buf[digest_len];
  unsigned int size;
  if (1 != EVP_DigestFinal_ex(mdctx, digest_buf, &size)) {
    PEACEMAKR_ERROR("digestfinal_ex failed");
    return;
  }

  if (size != digest_len) {
    PEACEMAKR_ERROR("sizes different than expected for message digest");
    return;
  }

  Buffer_set_bytes(digest, digest_buf, digest_len);

  EVP_MD_CTX_destroy(mdctx);
}

const uint8_t *serialize_blob(ciphertext_blob_t *cipher, size_t *out_size) {
  size_t buffer_len = sizeof(uint32_t); // magic number
  buffer_len += sizeof(uint64_t);       // size of message up until digest
  buffer_len += sizeof(uint32_t);       // version
  buffer_len +=
      sizeof(uint32_t) * 4; // encryption mode, ciphers, and digest algo

  const buffer_t *encrypted_key = CiphertextBlob_encrypted_key(cipher);
  if (encrypted_key != NULL) {
    buffer_len += sizeof(uint32_t);
    buffer_len += Buffer_get_size(encrypted_key);
  }

  const buffer_t *iv = CiphertextBlob_iv(cipher);
  if (iv != NULL) {
    buffer_len += sizeof(uint32_t);
    buffer_len += Buffer_get_size(iv);
  }

  const buffer_t *tag = CiphertextBlob_tag(cipher);
  if (iv != NULL) {
    buffer_len += sizeof(uint32_t);
    buffer_len += Buffer_get_size(tag);
  }

  const buffer_t *aad = CiphertextBlob_aad(cipher);
  if (iv != NULL) {
    buffer_len += sizeof(uint32_t);
    buffer_len += Buffer_get_size(aad);
  }

  const buffer_t *ciphertext = CiphertextBlob_ciphertext(cipher);
  if (iv != NULL) {
    buffer_len += sizeof(uint32_t);
    buffer_len += Buffer_get_size(ciphertext);
  }

  buffer_t *digest = CiphertextBlob_mutable_digest(cipher);
  if (iv != NULL) {
    buffer_len += sizeof(uint32_t);
    buffer_len += Buffer_get_size(digest);
  }

  uint8_t *buf = calloc(buffer_len, sizeof(uint8_t));

  *((uint32_t *)buf) = htonl(_PEACEMAKR_MAGIC_);
  size_t current_pos = sizeof(uint32_t);

  *((uint64_t *)(buf + current_pos)) = 0;
  current_pos += sizeof(uint64_t);

  *((uint32_t *)(buf + current_pos)) =
      htonl(CiphertextBlob_digest_algo(cipher));
  current_pos += sizeof(uint32_t);

  *((uint32_t *)(buf + current_pos)) = htonl(CiphertextBlob_version(cipher));
  current_pos += sizeof(uint32_t);

  *((uint32_t *)(buf + current_pos)) =
      htonl(CiphertextBlob_encryption_mode(cipher));
  current_pos += sizeof(uint32_t);

  *((uint32_t *)(buf + current_pos)) =
      htonl(CiphertextBlob_symm_cipher(cipher));
  current_pos += sizeof(uint32_t);

  *((uint32_t *)(buf + current_pos)) =
      htonl(CiphertextBlob_asymm_cipher(cipher));
  current_pos += sizeof(uint32_t);

  if (encrypted_key != NULL) {
    size_t bufsize = Buffer_get_size(encrypted_key);
    *((size_t *)buf + current_pos) = htonl(bufsize);
    current_pos += sizeof(size_t);
    memcpy(buf + current_pos, Buffer_get_bytes(encrypted_key, NULL), bufsize);
    current_pos += bufsize;
  } else {
    *((size_t *)buf + current_pos) = htonl(0);
    current_pos += sizeof(size_t);
  }

  if (iv != NULL) {
    size_t bufsize = Buffer_get_size(iv);
    *((size_t *)buf + current_pos) = htonl(bufsize);
    current_pos += sizeof(size_t);
    memcpy(buf + current_pos, Buffer_get_bytes(iv, NULL), bufsize);
    current_pos += bufsize;
  } else {
    *((size_t *)buf + current_pos) = htonl(0);
    current_pos += sizeof(size_t);
  }

  if (tag != NULL) {
    size_t bufsize = Buffer_get_size(tag);
    *((size_t *)buf + current_pos) = htonl(bufsize);
    current_pos += sizeof(size_t);
    memcpy(buf + current_pos, Buffer_get_bytes(tag, NULL), bufsize);
    current_pos += bufsize;
  } else {
    *((size_t *)buf + current_pos) = htonl(0);
    current_pos += sizeof(size_t);
  }

  if (aad != NULL) {
    size_t bufsize = Buffer_get_size(aad);
    *((size_t *)buf + current_pos) = htonl(bufsize);
    current_pos += sizeof(size_t);
    memcpy(buf + current_pos, Buffer_get_bytes(aad, NULL), bufsize);
    current_pos += bufsize;
  } else {
    *((size_t *)buf + current_pos) = htonl(0);
    current_pos += sizeof(size_t);
  }

  if (ciphertext != NULL) {
    size_t bufsize = Buffer_get_size(ciphertext);
    *((size_t *)buf + current_pos) = htonl(bufsize);
    current_pos += sizeof(size_t);
    memcpy(buf + current_pos, Buffer_get_bytes(ciphertext, NULL), bufsize);
    current_pos += bufsize;
  } else {
    *((size_t *)buf + current_pos) = htonl(0);
    current_pos += sizeof(size_t);
  }

  *((uint64_t *)(buf + sizeof(uint32_t))) =
      htonl(current_pos); // set the size of the buffer until the digest

  if (digest != NULL) {
    digest_message(buf, current_pos,
                   parse_digest(CiphertextBlob_digest_algo(cipher)), digest);

    size_t bufsize = Buffer_get_size(digest);
    *((size_t *)buf + current_pos) = htonl(bufsize);
    current_pos += sizeof(size_t);
    memcpy(buf + current_pos, Buffer_get_bytes(digest, NULL), bufsize);
    current_pos += bufsize;
  } else {
    *((size_t *)buf + current_pos) = htonl(0);
    current_pos += sizeof(size_t);
  }

  *out_size = current_pos;
  return buf;
}

const ciphertext_blob_t *deserialize_blob(const uint8_t *serialized_cipher) {

  size_t current_position = 0;
  uint32_t magic = ntohl(*(serialized_cipher + current_position));
  if (magic != _PEACEMAKR_MAGIC_) {
    PEACEMAKR_ERROR("magic number corrupted/missing, aborting");
    return NULL;
  }
  current_position += sizeof(uint32_t);

  uint64_t len_before_digest = ntohl(*(serialized_cipher + current_position));
  current_position += sizeof(uint64_t);

  message_digest_algorithm digest_algo =
      ntohl(*(serialized_cipher + current_position));

  size_t digest_size = (size_t)EVP_MD_size(parse_digest(digest_algo));
  size_t serialized_digest_size =
      htonl(*((size_t *)serialized_cipher + len_before_digest));

  if (serialized_digest_size != digest_size) {
    PEACEMAKR_ERROR("serialized digest is not of the correct length, aborting");
    return NULL;
  }

  buffer_t *digest_buf = Buffer_new(digest_size);
  digest_message(serialized_cipher, len_before_digest,
                 parse_digest(digest_algo), digest_buf);

  const uint8_t *serialized_digest_ptr =
      serialized_cipher + len_before_digest + sizeof(size_t);

  int rc = memcmp(Buffer_get_bytes(digest_buf, NULL), serialized_digest_ptr,
                  digest_size);
  if (rc != 0) {
    PEACEMAKR_ERROR("digests don't compare equal, aborting");
    return NULL;
  }

  // now start going through and deserializing the stuff

  //  ciphertext_blob_t *out = CiphertextBlob_new();

  return NULL;
}
