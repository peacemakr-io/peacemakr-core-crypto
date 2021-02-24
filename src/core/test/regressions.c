//
// Created by Aman LaChapelle on 2019-07-25.
//
// peacemakr_core_crypto
// Copyright (c) 2019 Aman LaChapelle
// Full license at peacemakr_core_crypto/LICENSE.txt
//

#include <assert.h>
#include <memory.h>
#include <peacemakr/crypto.h>

#include "utils/helper.h"

void test_uninit_crash() {
  crypto_config_t cfg = {.mode = SYMMETRIC,
                         .symm_cipher = AES_128_GCM,
                         .asymm_cipher = ASYMMETRIC_UNSPECIFIED,
                         .digest_algorithm = SHA_256};

  plaintext_t plaintext_in = {.data = (const unsigned char *)"Hello world!",
                              .data_len = 12 + 1,
                              .aad = NULL,
                              .aad_len = 0};

  plaintext_t plaintext_out;

  random_device_t rand = get_default_random_device();

  peacemakr_key_t *key = peacemakr_key_new_symmetric(AES_128_GCM, &rand);

  ciphertext_blob_t *ciphertext = peacemakr_encrypt(key, &plaintext_in, &rand);
  assert(ciphertext != NULL);

  size_t out_size = 0;
  uint8_t *serialized = peacemakr_serialize(SHA_256, ciphertext, &out_size);
  assert(serialized != NULL);

  crypto_config_t out_cfg;

  ciphertext_blob_t *deserialized =
      peacemakr_deserialize(serialized, out_size, &out_cfg);

  peacemakr_global_free(serialized);

  decrypt_code success = peacemakr_decrypt(key, deserialized, &plaintext_out);

  assert((out_cfg.mode == cfg.mode) &&
         (out_cfg.asymm_cipher == cfg.asymm_cipher) &&
         (out_cfg.symm_cipher == cfg.symm_cipher) &&
         (out_cfg.digest_algorithm == cfg.digest_algorithm));

  assert(success == DECRYPT_SUCCESS);

  assert(strncmp((const char *)plaintext_out.data,
                 (const char *)plaintext_in.data, plaintext_in.data_len) == 0);
  peacemakr_global_free((void *)plaintext_out.data);
  if (plaintext_in.aad != NULL) {
    assert(strncmp((const char *)plaintext_out.aad,
                   (const char *)plaintext_in.aad, plaintext_in.aad_len) == 0);
    peacemakr_global_free((void *)plaintext_out.aad);
  }

  peacemakr_key_free(key);
}

void test_wrong_header() {
  const char *msg =
      "AAAEHgAAAwsAAAAAAgAAAAEBBAEAAAEAAAAAAJVkfmpiAYBoCnczS0c2GS2p2foFJhPnfAM2"
      "T1vBpxJP3m969yQsjBhJoEl9tzXf3Mv/64t67WiC5j1pUez306bMmivI9eK75S0+bGYpAQnm"
      "lRauvETENzmLCvCuYCr8NxfAheCvEnJx83WGxW2rXpIqlDXh9r/UUGE9W0MnTTBeAv+Ef/Jy"
      "o8HTwUYez4LgRk7I47dqYHcCqb8OZ0TCAjVMSECjlKNwZ7iTOqo0h+IQVAsOaGF1HUUh73jM"
      "feOx4M16s9UlS5LI7/TH9UY4D20C7nG7FguRvQsPnCWD+6Du1KeELeLOpZpEoL1HPVCXI67l"
      "TOU4dlopObYJuFINShgAAAAQAAAAAIp+RsLFQCaRoQ0CSwAAAAAAAAAQAAAAAHLIqUwVG5Ce"
      "ZbAwya3XFUYAAABPAAAAAHsiY3J5cHRvS2V5SUQiOiIiLCJzZW5kZXJLZXlJRCI6IjNacEx1"
      "VDR1djhUTHFSTHlHTXFVQ09xelhQRjQwVldKREF1M1dqaDgrdTA9In0AAABYAAAAABvS1+k5"
      "CLtBSWuDKVW/Rxbygr5aioJQT2lPsptxSMxwtfWDSqHOqkdoOyx6m+iIX9UPJt72y2TeWWVD"
      "TFrH+mmHNsOfok83qcP7MYhxnfqsgjlnPrCj2/cAAAEAAAAAAGXL48F/0Z8NRBtHpjVPM0KS"
      "UBVkZU0Dl0sivWjlGpofTBWBiTXWrkE2LlnyNsLiLexTJVCMkyXRsOPjC9xMztTO3tirO+Ue"
      "ygfvRuEJBj9s1hKrVO+3ynTgpMGMPXaRvrBQaRmyqZsdY4ALciyEMaXSBEbIPIExxubBuH11"
      "YUO3YCyopO7DZmyv1gUQXsj+v6ETTxjNZtR+3RgUm4pwaVoE0+U49FZBxcLhSk+CtAZrnJ9Q"
      "zp6T5GSjcP5e1SaUwRahW2CksF6IEn+15aekL8hkfw2ymdaHgT9tReqoCHi6aAtqIFePa56t"
      "O3Ks+BF4VYGGx4QHp82jyLQ1pSvJNWAAAAAgAAAAAM4oJerNH9Vj3mQHp+jRsSPg6ncz2b9S"
      "7kH8OVSwQJ4y";
  const size_t msglen = strlen(msg);

  crypto_config_t cfg;
  ciphertext_blob_t *deserialized =
      peacemakr_deserialize((const uint8_t *)msg, msglen, &cfg);
  assert(deserialized == NULL);
}

int main() {
  if (!peacemakr_init()) {
    return 1;
  }

  test_uninit_crash();
  test_wrong_header();
}
