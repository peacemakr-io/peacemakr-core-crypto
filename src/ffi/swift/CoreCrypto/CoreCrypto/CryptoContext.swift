//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//
import Foundation

import libCoreCrypto

enum PeacemakrError: Error {
  case initializationFailed
  case encryptionFailed
  case serializationFailed
  case deserializationFailed
  case decryptionFailed
}

class CryptoContext {
  init() throws {
    if !peacemakr_init() {
      throw PeacemakrError.initializationFailed
    }
  }

  func Encrypt(key: PeacemakrKey, plaintext: inout plaintext_t, rand: inout random_device_t) throws -> [UInt8] {
    let ciphertext_blob = peacemakr_encrypt(key.internalRepr, &plaintext, &rand)
    if ciphertext_blob == nil {
      throw PeacemakrError.encryptionFailed
    }

    var out_size: size_t = 0
    let bytes = serialize_blob(ciphertext_blob, &out_size)
    if bytes == nil {
      throw PeacemakrError.serializationFailed
    }

    return Array(UnsafeBufferPointer(start: bytes, count: out_size))
  }

  func ExtractUnverifiedAAD(serialized: [UInt8]) throws -> plaintext_t {
    let ciphertext_blob = deserialize_blob(UnsafePointer(serialized), serialized.count)
    if ciphertext_blob == nil {
      throw PeacemakrError.deserializationFailed
    }

    var out = plaintext_t(data: nil, data_len: 0, aad: nil, aad_len: 0)
    if !peacemakr_decrypt(nil, ciphertext_blob, &out) {
      throw PeacemakrError.decryptionFailed
    }
    return out
  }

  func Decrypt(key: PeacemakrKey, serialized: [UInt8]) throws -> plaintext_t {
    let ciphertext_blob = deserialize_blob(UnsafePointer(serialized), serialized.count)
    if ciphertext_blob == nil {
      throw PeacemakrError.deserializationFailed
    }

    var out = plaintext_t(data: nil, data_len: 0, aad: nil, aad_len: 0)
    if !peacemakr_decrypt(key.internalRepr, ciphertext_blob, &out) {
      throw PeacemakrError.decryptionFailed
    }
    return out
  }
}
