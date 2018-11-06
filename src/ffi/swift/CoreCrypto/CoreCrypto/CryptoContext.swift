//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//
import Foundation

import libCoreCrypto

public enum PeacemakrError: Error {
  case initializationFailed
  case encryptionFailed
  case serializationFailed
  case deserializationFailed
  case decryptionFailed
}

public class CryptoContext {
  public init() throws {
    if !peacemakr_init() {
      throw PeacemakrError.initializationFailed
    }
  }

  public func Encrypt(key: PeacemakrKey, plaintext: Plaintext, rand: RandomDevice) throws -> [UInt8] {
    var innerRand = rand.getInternal()
    var innerPlaintext = plaintext.getInternal()
    let ciphertext_blob = peacemakr_encrypt(key.getInternal(), &innerPlaintext, &innerRand)
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

  public func ExtractUnverifiedAAD(serialized: [UInt8]) throws -> Plaintext {
    let ciphertext_blob = deserialize_blob(UnsafePointer(serialized), serialized.count)
    if ciphertext_blob == nil {
      throw PeacemakrError.deserializationFailed
    }

    var out = plaintext_t(data: nil, data_len: 0, aad: nil, aad_len: 0)
    if !peacemakr_decrypt(nil, ciphertext_blob, &out) {
      throw PeacemakrError.decryptionFailed
    }
    return Plaintext(cstyle: out)
  }

  public func Decrypt(key: PeacemakrKey, serialized: [UInt8]) throws -> Plaintext {
    let ciphertext_blob = deserialize_blob(UnsafePointer(serialized), serialized.count)
    if ciphertext_blob == nil {
      throw PeacemakrError.deserializationFailed
    }

    var out = plaintext_t(data: nil, data_len: 0, aad: nil, aad_len: 0)
    if !peacemakr_decrypt(key.getInternal(), ciphertext_blob, &out) {
      throw PeacemakrError.decryptionFailed
    }
    return Plaintext(cstyle: out)
  }
}
