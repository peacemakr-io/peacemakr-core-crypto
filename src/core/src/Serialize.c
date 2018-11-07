//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include <crypto.h>

#include "Buffer.h"
#include "CiphertextBlob.h"
#include "EVPHelper.h"
#include "Logging.h"
#include "b64.h"

#include <arpa/inet.h>
#include <memory.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

#define _PEACEMAKR_MAGIC_ (uint32_t)1054

static void digest_message(const unsigned char *message, size_t message_len,
                           const EVP_MD *digest_algo, buffer_t *digest) {
  EVP_MD_CTX *mdctx;

  mdctx = EVP_MD_CTX_create();
  EXPECT_NOT_NULL_RET_NONE(mdctx, "mdctx_create failed\n");

  OPENSSL_CHECK_RET_NONE(EVP_DigestInit_ex(mdctx, digest_algo, NULL),
                         EVP_MD_CTX_destroy(mdctx));
  OPENSSL_CHECK_RET_NONE(EVP_DigestUpdate(mdctx, message, message_len),
                         EVP_MD_CTX_destroy(mdctx));

  size_t digest_len = Buffer_get_size(digest);
  unsigned int size;

  OPENSSL_CHECK_RET_NONE(
      EVP_DigestFinal_ex(mdctx, Buffer_mutable_bytes(digest), &size),
      EVP_MD_CTX_destroy(mdctx));

  EXPECT_TRUE_CLEANUP_RET_NONE(
      (size == digest_len), EVP_MD_CTX_free(mdctx),
      "sizes different than expected for message digest\n");

  EVP_MD_CTX_free(mdctx);
}

uint8_t *serialize_blob(ciphertext_blob_t *cipher, size_t *out_size) {
  EXPECT_TRUE_RET((cipher != NULL && out_size != NULL),
                  "cipher or out_size was null in call to serialize\n");

  size_t buffer_len = sizeof(uint32_t); // magic number
  buffer_len += sizeof(uint64_t);       // size of message up until digest
  buffer_len += sizeof(uint32_t);       // digest algo
  // version, encryption mode, symm_cipher, asymm_cipher
  buffer_len += sizeof(uint32_t) * 4;

  const buffer_t *encrypted_key = CiphertextBlob_encrypted_key(cipher);
  buffer_len += sizeof(size_t);
  if (encrypted_key != NULL) {
    buffer_len += Buffer_get_size(encrypted_key);
  }

  const buffer_t *iv = CiphertextBlob_iv(cipher);
  buffer_len += sizeof(size_t);
  if (iv != NULL) {
    buffer_len += Buffer_get_size(iv);
  }

  const buffer_t *tag = CiphertextBlob_tag(cipher);
  buffer_len += sizeof(size_t);
  if (tag != NULL) {
    buffer_len += Buffer_get_size(tag);
  }

  const buffer_t *aad = CiphertextBlob_aad(cipher);
  buffer_len += sizeof(size_t);
  if (aad != NULL) {
    buffer_len += Buffer_get_size(aad);
  }

  const buffer_t *ciphertext = CiphertextBlob_ciphertext(cipher);
  buffer_len += sizeof(size_t);
  if (ciphertext != NULL) {
    buffer_len += Buffer_get_size(ciphertext);
  }

  buffer_t *digest = CiphertextBlob_mutable_digest(cipher);
  buffer_len += sizeof(size_t);
  if (digest != NULL) {
    buffer_len += Buffer_get_size(digest);
  }

  uint8_t *buf = alloca(buffer_len * sizeof(uint8_t));

  // magic
  uint32_t magic = htonl(_PEACEMAKR_MAGIC_);
  memcpy(buf, &magic, sizeof(uint32_t));
  size_t current_pos = sizeof(uint32_t);

  // len until digest
  memset((buf + current_pos), 0, sizeof(uint64_t));
  current_pos += sizeof(uint64_t);

  // digest algo
  uint32_t digest_algo = htonl(CiphertextBlob_digest_algo(cipher));
  memcpy(buf + current_pos, &digest_algo, sizeof(uint32_t));
  current_pos += sizeof(uint32_t);

  // version
  uint32_t version = htonl(CiphertextBlob_version(cipher));
  memcpy(buf + current_pos, &version, sizeof(uint32_t));
  current_pos += sizeof(uint32_t);

  // encryption mode
  uint32_t encryption_mode = htonl(CiphertextBlob_encryption_mode(cipher));
  memcpy(buf + current_pos, &encryption_mode, sizeof(uint32_t));
  current_pos += sizeof(uint32_t);

  // symm cipher
  uint32_t symm_cipher = htonl(CiphertextBlob_symm_cipher(cipher));
  memcpy(buf + current_pos, &symm_cipher, sizeof(uint32_t));
  current_pos += sizeof(uint32_t);

  // asymm cipher
  uint32_t asymm_cipher = htonl(CiphertextBlob_asymm_cipher(cipher));
  memcpy(buf + current_pos, &asymm_cipher, sizeof(uint32_t));
  current_pos += sizeof(uint32_t);

  if (encrypted_key != NULL) {
    size_t bufsize = htonl(Buffer_get_size(encrypted_key));
    memcpy(buf + current_pos, &bufsize, sizeof(size_t));
    current_pos += sizeof(size_t);
    memcpy(buf + current_pos, Buffer_get_bytes(encrypted_key, NULL),
           ntohl(bufsize));
    current_pos += ntohl(bufsize);
  } else {
    memset((buf + current_pos), 0, sizeof(size_t));
    current_pos += sizeof(size_t);
  }

  if (iv != NULL) {
    size_t bufsize = htonl(Buffer_get_size(iv));
    memcpy(buf + current_pos, &bufsize, sizeof(size_t));
    current_pos += sizeof(size_t);
    memcpy(buf + current_pos, Buffer_get_bytes(iv, NULL), ntohl(bufsize));
    current_pos += ntohl(bufsize);
  } else {
    memset((buf + current_pos), 0, sizeof(size_t));
    current_pos += sizeof(size_t);
  }

  if (tag != NULL) {
    size_t bufsize = htonl(Buffer_get_size(tag));
    memcpy(buf + current_pos, &bufsize, sizeof(size_t));
    current_pos += sizeof(size_t);
    memcpy(buf + current_pos, Buffer_get_bytes(tag, NULL), ntohl(bufsize));
    current_pos += ntohl(bufsize);
  } else {
    memset((buf + current_pos), 0, sizeof(size_t));
    current_pos += sizeof(size_t);
  }

  if (aad != NULL) {
    size_t bufsize = htonl(Buffer_get_size(aad));
    memcpy(buf + current_pos, &bufsize, sizeof(size_t));
    current_pos += sizeof(size_t);
    memcpy(buf + current_pos, Buffer_get_bytes(aad, NULL), ntohl(bufsize));
    current_pos += ntohl(bufsize);
  } else {
    memset((buf + current_pos), 0, sizeof(size_t));
    current_pos += sizeof(size_t);
  }

  if (ciphertext != NULL) {
    size_t bufsize = htonl(Buffer_get_size(ciphertext));
    memcpy(buf + current_pos, &bufsize, sizeof(size_t));
    current_pos += sizeof(size_t);
    memcpy(buf + current_pos, Buffer_get_bytes(ciphertext, NULL),
           ntohl(bufsize));
    current_pos += ntohl(bufsize);
  } else {
    memset((buf + current_pos), 0, sizeof(size_t));
    current_pos += sizeof(size_t);
  }

  // set the size of the buffer until the digest
  uint64_t curr_pos = htonl(current_pos);
  memcpy(buf + sizeof(uint32_t), &curr_pos, sizeof(uint64_t));

  if (digest != NULL) {
    // If it's ASYMMETRIC we already filled in the digest buffer
    if (CiphertextBlob_encryption_mode(cipher) == SYMMETRIC) {
      digest_message(buf, current_pos,
                     parse_digest(CiphertextBlob_digest_algo(cipher)), digest);
    }

    size_t bufsize = htonl(Buffer_get_size(digest));
    memcpy(buf + current_pos, &bufsize, sizeof(size_t));
    current_pos += sizeof(size_t);
    memcpy(buf + current_pos, Buffer_get_bytes(digest, NULL), ntohl(bufsize));
    current_pos += ntohl(bufsize);
  } else {
    memset((buf + current_pos), 0, sizeof(size_t));
    current_pos += sizeof(size_t);
  }

  CiphertextBlob_free(cipher);
  cipher = NULL;

  return (uint8_t *)b64_encode(buf, current_pos, out_size);
}

ciphertext_blob_t *deserialize_blob(const uint8_t *b64_serialized_cipher,
                                    size_t serialized_len) {

  EXPECT_TRUE_RET((b64_serialized_cipher != NULL && serialized_len != 0),
                  "b64 serialized cipher was NULL or serialized len was 0\n");

  uint8_t *serialized_cipher = alloca(serialized_len);
  int rc = b64_decode((const char *)b64_serialized_cipher, serialized_cipher,
                      serialized_len);

  EXPECT_TRUE_RET((serialized_cipher != NULL && rc == 1),
                  "b64 decode failed\n");

  size_t current_position = 0;
  uint32_t magic = ntohl(*(uint32_t *)serialized_cipher);
  EXPECT_TRUE_RET((magic == _PEACEMAKR_MAGIC_),
                  "magic number corrupted/missing, aborting\n");
  current_position += sizeof(uint32_t);

  uint64_t len_before_digest =
      ntohl(*(uint64_t *)(serialized_cipher + current_position));
  current_position += sizeof(uint64_t);

  message_digest_algorithm digest_algo =
      ntohl(*(uint32_t *)(serialized_cipher + current_position));
  current_position += sizeof(uint32_t);

  uint64_t digestlen = (size_t)EVP_MD_size(parse_digest(digest_algo));
  uint64_t serialized_digest_size =
      ntohl(*(uint64_t *)(serialized_cipher + len_before_digest));

  buffer_t *digest_buf = Buffer_new(digestlen);
  digest_message(serialized_cipher, len_before_digest,
                 parse_digest(digest_algo), digest_buf);

  const uint8_t *serialized_digest_ptr =
      serialized_cipher + len_before_digest + sizeof(size_t);

  // version
  uint32_t version =
      ntohl(*((uint32_t *)(serialized_cipher + current_position)));
  current_position += sizeof(uint32_t);
  if (version > PEACEMAKR_CORE_CRYPTO_VERSION_MAX) {
    PEACEMAKR_LOG("version greater than max supported");
    Buffer_free(digest_buf);
    return NULL;
  }

  // encryption mode
  uint32_t encryption_mode =
      ntohl(*((uint32_t *)(serialized_cipher + current_position)));
  current_position += sizeof(uint32_t);

  EXPECT_TRUE_RET(
      (serialized_digest_size == digestlen || encryption_mode == ASYMMETRIC),
      "serialized digest is not of the correct length, aborting\n");

  rc = CRYPTO_memcmp(Buffer_get_bytes(digest_buf, NULL), serialized_digest_ptr,
                     digestlen);
  if (rc != 0 && encryption_mode != ASYMMETRIC) {
    PEACEMAKR_LOG("digests don't compare equal, aborting\n");
    Buffer_free(digest_buf);
    return NULL;
  }

  // If it's asymmetric encryption, leave the veriification to the decrypt
  // function.
  if (encryption_mode == ASYMMETRIC) {
    Buffer_set_size(digest_buf, serialized_digest_size);
    Buffer_set_bytes(digest_buf, serialized_digest_ptr, serialized_digest_size);
    digestlen = serialized_digest_size;
  }

  // symm_cipher
  uint32_t symm_cipher =
      ntohl(*((uint32_t *)(serialized_cipher + current_position)));
  current_position += sizeof(uint32_t);

  // asymm_cipher
  uint32_t asymm_cipher =
      ntohl(*((uint32_t *)(serialized_cipher + current_position)));
  current_position += sizeof(uint32_t);

  crypto_config_t cfg = {.mode = encryption_mode,
                         .symm_cipher = symm_cipher,
                         .asymm_cipher = asymm_cipher,
                         .digest_algorithm = digest_algo};

  // encrypted key
  size_t keylen = ntohl(*((size_t *)(serialized_cipher + current_position)));
  current_position += sizeof(size_t);
  uint8_t *encrypted_key = NULL;
  if (keylen != 0) {
    encrypted_key = alloca(keylen);
    memcpy(encrypted_key, serialized_cipher + current_position, keylen);
    current_position += keylen;
  }

  // iv
  size_t ivlen = ntohl(*((size_t *)(serialized_cipher + current_position)));
  current_position += sizeof(size_t);
  uint8_t *iv = NULL;
  if (ivlen != 0) {
    iv = alloca(ivlen);
    memcpy(iv, serialized_cipher + current_position, ivlen);
    current_position += ivlen;
  }

  // tag
  size_t taglen = ntohl(*((size_t *)(serialized_cipher + current_position)));
  current_position += sizeof(size_t);
  uint8_t *tag = NULL;
  if (taglen != 0) {
    tag = alloca(taglen);
    memcpy(tag, serialized_cipher + current_position, taglen);
    current_position += taglen;
  }

  // aad
  size_t aadlen = ntohl(*((size_t *)(serialized_cipher + current_position)));
  current_position += sizeof(size_t);
  uint8_t *aad = NULL;
  if (aadlen != 0) {
    aad = alloca(aadlen);
    memcpy(aad, serialized_cipher + current_position, aadlen);
    current_position += aadlen;
  }

  // ciphertext
  size_t cipherlen = ntohl(*((size_t *)(serialized_cipher + current_position)));
  current_position += sizeof(size_t);
  uint8_t *ciphertext = NULL;
  if (cipherlen != 0) {
    ciphertext = alloca(cipherlen);
    memcpy(ciphertext, serialized_cipher + current_position, cipherlen);
    //    current_position += cipherlen;
  }

  ciphertext_blob_t *out =
      CiphertextBlob_new(cfg, ivlen, taglen, aadlen, cipherlen, digestlen);
  CiphertextBlob_set_version(out, version);

  if (encrypted_key != NULL) {
    Buffer_set_bytes(CiphertextBlob_mutable_encrypted_key(out), encrypted_key,
                     keylen);
  }

  if (iv != NULL) {
    CiphertextBlob_set_iv(out, iv, ivlen);
  }

  if (tag != NULL) {
    Buffer_set_bytes(CiphertextBlob_mutable_tag(out), tag, taglen);
  }

  if (aad != NULL) {
    Buffer_set_bytes(CiphertextBlob_mutable_aad(out), aad, aadlen);
  }

  if (ciphertext != NULL) {
    Buffer_set_bytes(CiphertextBlob_mutable_ciphertext(out), ciphertext,
                     cipherlen);
  }

  Buffer_set_bytes(CiphertextBlob_mutable_digest(out),
                   Buffer_get_bytes(digest_buf, NULL), digestlen);

  Buffer_free(digest_buf);

  return out;
}
