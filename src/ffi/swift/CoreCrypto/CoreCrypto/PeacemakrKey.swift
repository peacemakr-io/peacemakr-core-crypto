//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

import Foundation

import libCoreCrypto

enum PeacemakrKeyError: Error {
  case allocationFailed
}

class PeacemakrKey {
  var internalRepr: OpaquePointer
    
  init(config: crypto_config_t, rand: inout random_device_t) throws {
    internalRepr = PeacemakrKey_new(config, &rand)!
  }

  init(config: crypto_config_t, bytes: [UInt8]) throws {
    internalRepr = PeacemakrKey_new_bytes(config, UnsafePointer(bytes), bytes.count)!
  }

  init(config: crypto_config_t, master: PeacemakrKey, bytes: [UInt8]) throws {
    internalRepr = PeacemakrKey_new_from_master(config, master.internalRepr, UnsafePointer(bytes), bytes.count)!
  }

    // TODO: WTF why does this segfault xcode
//  init(config: crypto_config_t, fileContents: String, is_priv: Bool) throws {
//    internalRepr = PeacemakrKey_new_pem(config, UnsafePointer(fileContents), fileContents.count, is_priv)!
//  }

  deinit {
    PeacemakrKey_free(internalRepr)
  }

  func getConfig() -> crypto_config_t {
    return PeacemakrKey_get_config(internalRepr)
  }
}
