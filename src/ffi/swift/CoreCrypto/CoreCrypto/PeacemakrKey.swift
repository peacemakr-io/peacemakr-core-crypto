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
}

public class PeacemakrKey {
  var internalRepr: OpaquePointer
    
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

    // TODO: WTF why does this segfault xcode
//  public init(config: CryptoConfig, fileContents: String, is_priv: Bool) throws {
//    internalRepr = PeacemakrKey_new_pem(config.getInternal(), UnsafePointer(fileContents), fileContents.count, is_priv)!
//  }

  deinit {
    PeacemakrKey_free(internalRepr)
  }

  func getConfig() -> CryptoConfig {
    return CryptoConfig(cfg: PeacemakrKey_get_config(internalRepr))
  }

  func getInternal() -> OpaquePointer {
    return internalRepr
  }
}
