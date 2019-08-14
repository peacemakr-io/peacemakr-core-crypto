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

public class CryptoContext: CryptoContextProtocol {
  
  /// MARK: - Initialization
  
  public class func setup() -> Bool {
    return peacemakr_init()
  }
  
  /// MARK: - CoreCrypto encryption and decryption
  
  public class func encrypt(recipientKey key: PeacemakrKey, plaintext: Plaintext, rand: RandomDevice) -> Result<Ciphertext> {
    var innerRand = rand.getInternal()
    var innerPlaintext = plaintext.getInternal()
    
    guard let ciphertext_blob = peacemakr_encrypt(key.getInternal(), &innerPlaintext, &innerRand) else {
      destroyPlaintext(cstyle: innerPlaintext)
      return .error(CoreCryptoError.encryptionFailed)
    }
    
    destroyPlaintext(cstyle: innerPlaintext)
    return .result(ciphertext_blob)
  }
  public class func decrypt(recipientKey key: PeacemakrKey, ciphertext: Ciphertext) -> Result<(Plaintext, Bool)> {
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
  
  /// MARK: - Signing
  
  public class func sign(senderKey: PeacemakrKey, plaintext: Plaintext, digest: MessageDigestAlgorithm, ciphertext: inout Ciphertext) -> Void {
    var innerPlaintext = plaintext.getInternal()
    peacemakr_sign(senderKey.getInternal(), &innerPlaintext, message_digest_algorithm(rawValue: digest.rawValue), ciphertext);
    destroyPlaintext(cstyle: innerPlaintext)
  }
  
  ///MARK: - Data serialization and deserialization
  
  public class func serialize(_ digest: MessageDigestAlgorithm, _ ciphertext_blob: Ciphertext) -> Result<Data> {
    var out_size: size_t = 0
    let bytes = peacemakr_serialize(message_digest_algorithm(rawValue: digest.rawValue), ciphertext_blob, &out_size)
    if bytes == nil {
      return .error(CoreCryptoError.serializationFailed)
    }

    return .result(Data(buffer: UnsafeBufferPointer(start: bytes, count: out_size)))
  }

  public class func deserialize(_ serialized: Data) -> Result<(Ciphertext, CryptoConfig)> {
    var out: Result<(Ciphertext, CryptoConfig)> = .error(CoreCryptoError.deserializationFailed)
    
    serialized.withUnsafeBytes { (serializedBytes: UnsafePointer<UInt8>) -> Void in
      var out_cfg_internal = crypto_config_t()
      if let ciphertext_blob = peacemakr_deserialize(serializedBytes, serialized.count, &out_cfg_internal) {
        out = .result((ciphertext_blob, CryptoConfig(cfg: out_cfg_internal)))
      } else {
        out = .error(CoreCryptoError.deserializationFailed)
      }
    }
  
    return out
  }

  
  /// MARK: - Verification

  public class func verify(senderKey: PeacemakrKey, plaintext: Plaintext, ciphertext: inout Ciphertext) -> Result<Bool> {
    var innerPlaintext = plaintext.getInternal()
    let verified = peacemakr_verify(senderKey.getInternal(), &innerPlaintext, ciphertext)
    destroyPlaintext(cstyle: innerPlaintext)
    if !verified {
      return .error(CoreCryptoError.verificationFailed)
    }
    return .result(true)
  }

  public class func HMAC(digestAlgorithm: MessageDigestAlgorithm, key: PeacemakrKey, buf: Data) -> Result<Data> {
    var out: Result<Data> = .error(CoreCryptoError.HMACFailed)
    buf.withUnsafeBytes { (bufBytes: UnsafePointer<UInt8>) -> Void in
      var outLen = 0
      let outPtr = peacemakr_hmac(message_digest_algorithm(digestAlgorithm.rawValue), key.getInternal(), bufBytes, buf.count, &outLen)
      if outPtr == nil {
        out = .error(CoreCryptoError.HMACFailed)
      }
      out = .result(Data(buffer: UnsafeBufferPointer(start: outPtr, count: outLen)))
    }
    
    return out
  }
  
  public class func extractUnverifiedAAD(_ serialized: Data) -> Result<Plaintext> {
    var out: Result<Plaintext> = .error(CoreCryptoError.deserializationFailed)
    
    serialized.withUnsafeBytes { (serializedBytes: UnsafePointer<UInt8>) -> Void in
      var out_cfg_internal = crypto_config_t()
      guard let ciphertext_blob = peacemakr_deserialize(serializedBytes, serialized.count, &out_cfg_internal) else {
        out = .error(CoreCryptoError.deserializationFailed)
        return
      }
      
      var plaintextOut = plaintext_t(data: nil, data_len: 0, aad: nil, aad_len: 0)
      if !peacemakr_get_unverified_aad(ciphertext_blob, &plaintextOut) {
        out = .error(CoreCryptoError.decryptionFailed)
        return
      }
      
      out = .result(Plaintext(cstyle: plaintextOut))
      return
    }
    
    return out
  }
}
