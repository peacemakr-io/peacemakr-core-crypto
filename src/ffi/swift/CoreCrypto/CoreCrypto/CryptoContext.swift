//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//
import Foundation

import libCoreCrypto

public typealias Ciphertext = OpaquePointer

public class CryptoContext {
  public init?(){
    if !peacemakr_init() {
      return nil
    }
  }

  public func Encrypt(key: PeacemakrKey, plaintext: Plaintext, rand: RandomDevice) -> Result<Ciphertext> {
    var innerRand = rand.getInternal()
    var innerPlaintext = plaintext.getInternal()
    let ciphertext_blob = peacemakr_encrypt(key.getInternal(), &innerPlaintext, &innerRand)
    if ciphertext_blob == nil {
      return .error(CoreCryptoError.encryptionFailed)
    }
    return .result(ciphertext_blob!)
  }

  public func Sign(senderKey: PeacemakrKey, plaintext: Plaintext, ciphertext: inout Ciphertext) -> Void {
    var innerPlaintext = plaintext.getInternal()
    peacemakr_sign(senderKey.getInternal(), &innerPlaintext, ciphertext);
  }

  public func Serialize(_ ciphertext_blob: Ciphertext) -> Result<[UInt8]> {
    var out_size: size_t = 0
    let bytes = peacemakr_serialize(ciphertext_blob, &out_size)
    if bytes == nil {
      return .error(CoreCryptoError.serializationFailed)
    }

    return .result(Array(UnsafeBufferPointer(start: bytes, count: out_size)))
  }

  public func ExtractUnverifiedAAD(_ serialized: [UInt8]) -> Result<Plaintext> {
    var out_cfg_internal = crypto_config_t()
    let ciphertext_blob = peacemakr_deserialize(UnsafePointer(serialized), serialized.count, &out_cfg_internal)
    if ciphertext_blob == nil {
      return .error(CoreCryptoError.deserializationFailed)
    }

    var out = plaintext_t(data: nil, data_len: 0, aad: nil, aad_len: 0)
    if !peacemakr_get_unverified_aad(ciphertext_blob, &out) {
      return .error(CoreCryptoError.decryptionFailed)
    }
    return .result(Plaintext(cstyle: out))
  }

  public func Deserialize(_ serialized: [UInt8]) -> Result<(Ciphertext, CryptoConfig)> {
    var out_cfg_internal = crypto_config_t()
    let ciphertext_blob = peacemakr_deserialize(UnsafePointer(serialized), serialized.count, &out_cfg_internal)
    if ciphertext_blob == nil {
      return .error(CoreCryptoError.deserializationFailed)
    }
    return .result((ciphertext_blob!, CryptoConfig(cfg: out_cfg_internal)))
  }

  public func Decrypt(key: PeacemakrKey, ciphertext: Ciphertext) -> Result<(Plaintext, Bool)> {
    var out = plaintext_t(data: nil, data_len: 0, aad: nil, aad_len: 0)
    let success = peacemakr_decrypt(key.getInternal(), ciphertext, &out)

    if success == DECRYPT_FAILED {
      return .error(CoreCryptoError.decryptionFailed)
    }

    var needVerify = false
    if success == DECRYPT_NEED_VERIFY {
      needVerify = true
    }

    return .result((Plaintext(cstyle: out), needVerify))
  }

  public func Verify(senderKey: PeacemakrKey, plaintext: Plaintext, ciphertext: inout Ciphertext) -> Result<Bool> {
    var innerPlaintext = plaintext.getInternal()
    let verified = peacemakr_verify(senderKey.getInternal(), &innerPlaintext, ciphertext)
    if !verified {
      return .error(CoreCryptoError.verificationFailed)
    }
    return .result(true)
  }

  public func HMAC(digestAlgorithm: MessageDigestAlgorithm, key: PeacemakrKey, buf: [UInt8]) -> Result<[UInt8]> {
    var outLen = 0
    let outPtr = peacemakr_hmac(message_digest_algorithm(digestAlgorithm.rawValue), key.getInternal(), UnsafePointer(buf), buf.count, &outLen)
    if outPtr == nil {
      return .error(CoreCryptoError.HMACFailed)
    }
    return .result(Array(UnsafeBufferPointer(start: outPtr, count: outLen)))
  }
}
