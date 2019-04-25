//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

import Foundation

import libCoreCrypto

public class PeacemakrKey {
  let internalRepr: OpaquePointer
    
  public init?(asymmCipher: AsymmetricCipher, symmCipher: SymmetricCipher, rand: RandomDevice) {
    var randInternal = rand.getInternal()
    let key = peacemakr_key_new_asymmetric(asymmetric_cipher(rawValue: asymmCipher.rawValue), symmetric_cipher(rawValue: symmCipher.rawValue), &randInternal)
    if key == nil {
      return nil
    }
    internalRepr = key!
  }
  
  public init?(symmCipher: SymmetricCipher, rand: RandomDevice) {
    var randInternal = rand.getInternal()
    let key = peacemakr_key_new_symmetric(symmetric_cipher(rawValue: symmCipher.rawValue), &randInternal)
    if key == nil {
      return nil
    }
    internalRepr = key!
  }

  public init?(symmCipher: SymmetricCipher, bytes: Data) {
    let key = bytes.withUnsafeBytes { (rawBytes: UnsafePointer<UInt8>) -> OpaquePointer? in
      return peacemakr_key_new_bytes(symmetric_cipher(rawValue: symmCipher.rawValue), rawBytes, bytes.count)
    }
    if key == nil {
      return nil
    }
    internalRepr = key!
  }
  
  // TODO: add initializer from password

  public init?(symmCipher: SymmetricCipher, digest: MessageDigestAlgorithm, master: PeacemakrKey, bytes: Data) {
    let key = bytes.withUnsafeBytes { (rawBytes) -> OpaquePointer? in
      return peacemakr_key_new_from_master(symmetric_cipher(rawValue: symmCipher.rawValue), message_digest_algorithm(rawValue: digest.rawValue), master.internalRepr, rawBytes, bytes.count)
    }
    if key == nil {
      return nil
    }
    internalRepr = key!
  }

  public init?(asymmCipher: AsymmetricCipher, symmCipher: SymmetricCipher, fileContents: String, isPriv: Bool) {
    let key = fileContents.withCString { (fileContentsPtr: UnsafePointer<CChar>) -> OpaquePointer in
      if isPriv {
        return peacemakr_key_new_pem_priv(asymmetric_cipher(rawValue: asymmCipher.rawValue), symmetric_cipher(rawValue: symmCipher.rawValue), fileContentsPtr, fileContents.count)!
      } else {
        return peacemakr_key_new_pem_pub(asymmetric_cipher(rawValue: asymmCipher.rawValue), symmetric_cipher(rawValue: symmCipher.rawValue), fileContentsPtr, fileContents.count)!
      }
    }
    
    internalRepr = key
  }

  public init?(symmCipher: SymmetricCipher, myKey: PeacemakrKey, peerKey: PeacemakrKey) {
    let key = peacemakr_key_dh_generate(symmetric_cipher(rawValue: symmCipher.rawValue), myKey.internalRepr, peerKey.internalRepr)

    if key == nil {
      return nil
    }

    internalRepr = key!
  }

  deinit {
    peacemakr_key_free(internalRepr)
  }

  func getConfig() -> CryptoConfig {
    return CryptoConfig(cfg: peacemakr_key_get_config(internalRepr))
  }

  func getInternal() -> OpaquePointer {
    return internalRepr
  }
  
  func getBytes() -> Data {
    var out: UnsafeMutablePointer<UInt8>?
    var outsize: CLong = 0
    if !peacemakr_key_get_bytes(internalRepr, &out, &outsize) {
      return Data()
    }
    
    if out == nil {
      return Data()
    }
    
    return Data(bytes: out!, count: outsize)
  }
  
  public func toPem(isPriv: Bool) -> Result<Data> {
    var out: UnsafeMutablePointer<CChar>?
    var outsize: CLong = 0
    if isPriv {
      if !peacemakr_key_priv_to_pem(internalRepr, &out, &outsize) {
        return .error(CoreCryptoError.serializationFailed)
      }
    } else {
      if !peacemakr_key_pub_to_pem(internalRepr, &out, &outsize) {
        return .error(CoreCryptoError.serializationFailed)
      }
    }
    
    let pemData = Data(buffer: UnsafeBufferPointer(start: out, count: outsize))
    return .result(pemData)
  }
  
  public func toPem(isPriv: Bool) -> Result<String> {
    let pemData: Result<Data> = self.toPem(isPriv: isPriv)
    switch (pemData) {
    case let .error(e):
      return .error(e)
    case let .result(pem):
      // We are assuming PEM is UTF8 compatible
      let pemString = String(data: pem, encoding: .utf8)
      if pemString == nil {
        return .error(CoreCryptoError.keySerializationFailed)
      }
      
      return .result(pemString!)
    }
  }
}
