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

  public init?(config: CryptoConfig, bytes: [UInt8]) {
    let key = PeacemakrKey_new_bytes(config.getInternal(), UnsafePointer(bytes), bytes.count)
    if key == nil {
      return nil
    }
    internalRepr = key!
  }

  public init?(config: CryptoConfig, master: PeacemakrKey, bytes: [UInt8]) {
    let key = PeacemakrKey_new_from_master(config.getInternal(), master.internalRepr, UnsafePointer(bytes), bytes.count)
    if key == nil {
      return nil
    }
    internalRepr = key!
  }

  public init?(config: CryptoConfig, fileContents: [CChar], is_priv: Bool) {
    var key: OpaquePointer? = nil
    if is_priv {
      key = PeacemakrKey_new_pem_priv(config.getInternal(), UnsafePointer(fileContents), fileContents.count)!
    } else {
      key = PeacemakrKey_new_pem_pub(config.getInternal(), UnsafePointer(fileContents), fileContents.count)!
    }
    
    if key == nil {
      return nil
    }
    
    internalRepr = key!
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
  
  public func toPem(is_priv: Bool) -> Result<[Int8]> {
    var out: UnsafeMutablePointer<Int8>?
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
    
    return .result(Array(UnsafeBufferPointer(start: out, count: outsize)))
  }
}
