//
// Copyright 2021 Peacemakr, Inc.
// Full license at peacemakr_core_crypto/LICENSE.txt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <assert.h>
#include <memory.h>
#include <peacemakr/crypto.h>

int main() {
  if (!peacemakr_init()) {
    return 1;
  }

  // Manually generated a certificate ca/ca.crt and used it to sign
  // child_cert.pem
  const char *tafile = PEACEMAKR_TEST_PEM_DIRECTORY "/ca/ca.crt";
  const char *certfile = PEACEMAKR_TEST_PEM_DIRECTORY "/child_cert.pem";
  FILE *cfile = fopen(certfile, "r");

  char *cert = NULL;
  size_t cert_len = 0;
  if (cfile) {
    // Seek the last byte of the file
    fseek(cfile, 0, SEEK_END);
    // Offset from the first to the last byte, or in other words, filesize
    cert_len = (size_t)ftell(cfile);
    // go back to the start of the file
    rewind(cfile);

    cert = peacemakr_global_malloc(cert_len + 1);

    size_t read_size = fread(cert, sizeof(char), cert_len, cfile);

    assert(read_size == cert_len);

    cert[cert_len] = '\0';

    fclose(cfile);
  }

  // Get the key from the certificate while validating the trust anchor
  peacemakr_key_t *key_from_cert = peacemakr_key_new_pem_pub(
      CHACHA20_POLY1305, cert, cert_len, tafile, strlen(tafile));
  assert(key_from_cert != NULL);

  // If I pass in the same cert (when it was issued by someone else) it should
  // fail to validate and I should NOT get a public key out of this function
  peacemakr_key_t *key_from_cert_shouldfail = peacemakr_key_new_pem_pub(
      CHACHA20_POLY1305, cert, cert_len, certfile, strlen(certfile));
  assert(key_from_cert_shouldfail == NULL);

  // Don't pass a trust store and make sure that works
  peacemakr_key_t *key_from_cert_no_vrf =
      peacemakr_key_new_pem_pub(CHACHA20_POLY1305, cert, cert_len, NULL, 0);
  assert(key_from_cert_no_vrf != NULL);

  peacemakr_key_free(key_from_cert);
  peacemakr_key_free(key_from_cert_no_vrf);
  peacemakr_global_free(cert);
}
