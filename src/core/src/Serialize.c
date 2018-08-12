//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include <Buffer.h>
#include <crypto.h>

#include <Logging.h>
#include <openssl/evp.h>

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

const uint8_t *serialize_blob(const ciphertext_blob_t *cipher) {
  return NULL; // TODO
}

const ciphertext_blob_t *deserialize_blob(const uint8_t *serialized_cipher) {
  return NULL; // TODO
}
