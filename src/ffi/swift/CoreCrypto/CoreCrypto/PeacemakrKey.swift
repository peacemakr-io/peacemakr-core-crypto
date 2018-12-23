//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

import Foundation

import libCoreCrypto

public enum PeacemakrKeyError: Error {
  case allocationFailed
  case serializationFailed
}

public class PeacemakrKey {
  let internalRepr: OpaquePointer
    
  public init(config: CryptoConfig, rand: RandomDevice) throws {
    var randInternal = rand.getInternal()
    internalRepr = PeacemakrKey_new(config.getInternal(), &randInternal)!
  }

  public init(config: CryptoConfig, bytes: [UInt8]) throws {
    internalRepr = PeacemakrKey_new_bytes(config.getInternal(), UnsafePointer(bytes), bytes.count)!
  }

  public init(config: CryptoConfig, master: PeacemakrKey, bytes: [UInt8]) throws {
    internalRepr = PeacemakrKey_new_from_master(config.getInternal(), master.internalRepr, UnsafePointer(bytes), bytes.count)!
  }

  public init(config: CryptoConfig, fileContents: [CChar], is_priv: Bool) throws {
    if is_priv {
      internalRepr = PeacemakrKey_new_pem_priv(config.getInternal(), UnsafePointer(fileContents), fileContents.count)!
    } else {
      internalRepr = PeacemakrKey_new_pem_pub(config.getInternal(), UnsafePointer(fileContents), fileContents.count)!
    }
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
  
  public func toPem(is_priv: Bool) throws -> [Int8] {
    var out: UnsafeMutablePointer<Int8>?
    var outsize: CLong = 0
    if is_priv {
      if !PeacemakrKey_priv_to_pem(internalRepr, &out, &outsize) {
        throw PeacemakrKeyError.serializationFailed
      }
    } else {
      if !PeacemakrKey_pub_to_pem(internalRepr, &out, &outsize) {
        throw PeacemakrKeyError.serializationFailed
      }
    }
    
    return [Int8](UnsafeBufferPointer(start: out, count: outsize))
  }
}
