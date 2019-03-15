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
    
  public init?(config: CryptoConfig, rand: RandomDevice) {
    var randInternal = rand.getInternal()
    let key = PeacemakrKey_new(config.getInternal(), &randInternal)
    if key == nil {
      return nil
    }
    internalRepr = key!
  }

  public init?(config: CryptoConfig, bytes: Data) {
    let key = bytes.withUnsafeBytes { (rawBytes: UnsafePointer<UInt8>) -> OpaquePointer in
      return PeacemakrKey_new_bytes(config.getInternal(), rawBytes, bytes.count)
    }
    internalRepr = key
  }

  public init?(config: CryptoConfig, master: PeacemakrKey, bytes: Data) {
    let key = bytes.withUnsafeBytes { (rawBytes: UnsafePointer<UInt8>) -> OpaquePointer in
      return PeacemakrKey_new_from_master(config.getInternal(), master.internalRepr, rawBytes, bytes.count)
    }
    internalRepr = key
  }

  public init?(config: CryptoConfig, fileContents: String, is_priv: Bool) {
    let key = fileContents.withCString { (fileContentsPtr: UnsafePointer<CChar>) -> OpaquePointer in
      if is_priv {
        return PeacemakrKey_new_pem_priv(config.getInternal(), fileContentsPtr, fileContents.count)!
      } else {
        return PeacemakrKey_new_pem_pub(config.getInternal(), fileContentsPtr, fileContents.count)!
      }
    }
    
    internalRepr = key
  }

  public init?(myKey: PeacemakrKey, peerKey: PeacemakrKey) {
    let key: OpaquePointer? = PeacemakrKey_dh_generate(myKey.internalRepr, peerKey.internalRepr)

    if key == nil {
      return nil
    }

    internalRepr = key!
  }

  deinit {
    PeacemakrKey_free(internalRepr)
  }

  func getConfig() -> CryptoConfig {
    return CryptoConfig(cfg: PeacemakrKey_get_config(internalRepr))
  }

  func getInternal() -> OpaquePointer {
    return internalRepr
  }
  
  public func toPem(is_priv: Bool) -> Result<Data> {
    var out: UnsafeMutablePointer<CChar>?
    var outsize: CLong = 0
    if is_priv {
      if !PeacemakrKey_priv_to_pem(internalRepr, &out, &outsize) {
        return .error(CoreCryptoError.serializationFailed)
      }
    } else {
      if !PeacemakrKey_pub_to_pem(internalRepr, &out, &outsize) {
        return .error(CoreCryptoError.serializationFailed)
      }
    }
    
    let pemData = Data(buffer: UnsafeBufferPointer(start: out, count: outsize))
    return .result(pemData)
  }
  
  public func toPem(is_priv: Bool) -> Result<String> {
    let pemData: Result<Data> = self.toPem(is_priv: is_priv)
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
