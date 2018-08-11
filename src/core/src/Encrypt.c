//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include <crypto.h>

#include <Key.h>
#include <CiphertextBlob.h>
#include <EVPHelper.h>

#include <openssl/evp.h>

ciphertext_blob_t *encrypt(crypto_config_t cfg, const peacemakr_key_t *key, const plaintext_t *plain) {

  const EVP_CIPHER *cipher = parse_cipher(cfg);
  size_t iv_len = EVP_CIPHER_iv_length(cipher);
  size_t tag_len = get_taglen(cfg);
  size_t aad_len = plain->aad_len;
  size_t ciphertext_len;
  size_t digest_len;

  ciphertext_blob_t *out = CiphertextBlob_new();
}

int decrypt(const peacemakr_key_t *key, const ciphertext_blob_t *cipher,
            plaintext_t *plain) {
  return 0; // TODO
}
