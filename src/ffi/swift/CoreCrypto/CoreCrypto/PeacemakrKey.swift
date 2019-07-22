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
    guard let key = peacemakr_key_new_asymmetric(asymmetric_cipher(rawValue: asymmCipher.rawValue), symmetric_cipher(rawValue: symmCipher.rawValue), &randInternal) else {
      return nil
    }
    internalRepr = key
  }
  
  public init?(symmCipher: SymmetricCipher, rand: RandomDevice) {
    var randInternal = rand.getInternal()
    guard let key = peacemakr_key_new_symmetric(symmetric_cipher(rawValue: symmCipher.rawValue), &randInternal) else {
      return nil
    }
    internalRepr = key
  }

  public init?(symmCipher: SymmetricCipher, bytes: Data) {
    let key = bytes.withUnsafeBytes { (rawBytes: UnsafePointer<UInt8>) -> OpaquePointer in
      return peacemakr_key_new_bytes(symmetric_cipher(rawValue: symmCipher.rawValue), rawBytes, bytes.count)
    }
    internalRepr = key
  }
  
  // TODO: add initializer from password
  public init?(symmCipher: SymmetricCipher, digest: MessageDigestAlgorithm, master: PeacemakrKey, bytes: Data) {
    let key = bytes.withUnsafeBytes { (rawBytes) -> OpaquePointer in
    return peacemakr_key_new_from_master(symmetric_cipher(rawValue: symmCipher.rawValue), message_digest_algorithm(rawValue: digest.rawValue), master.internalRepr, rawBytes, bytes.count)
    }
    internalRepr = key
  }

  public init?(symmCipher: SymmetricCipher, fileContents: String, isPriv: Bool) {
    let key = fileContents.withCString { (fileContentsPtr: UnsafePointer<CChar>) -> OpaquePointer in
      if isPriv {
        return peacemakr_key_new_pem_priv(symmetric_cipher(rawValue: symmCipher.rawValue), fileContentsPtr, fileContents.count)!
      } else {
        return peacemakr_key_new_pem_pub(symmetric_cipher(rawValue: symmCipher.rawValue), fileContentsPtr, fileContents.count)!
      }
    }
    
    internalRepr = key
  }

  public init?(symmCipher: SymmetricCipher, myKey: PeacemakrKey, peerKey: PeacemakrKey) {
    guard let key = peacemakr_key_dh_generate(symmetric_cipher(rawValue: symmCipher.rawValue), myKey.internalRepr, peerKey.internalRepr) else{
      return nil
    }

    internalRepr = key
  }
  
  private init?(cKey: OpaquePointer) {
    internalRepr = cKey
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
}

extension Data {
  public func toString() -> String {
    return String(data: self, encoding: String.Encoding.utf8) ?? ""
  }
}
