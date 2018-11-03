//
// Created by Aman LaChapelle on 11/2/18.
//

import Foundation

import libCoreCrypto

public class Plaintext {
  let data: [UInt8]
  let aad: [UInt8]

  public init(data: [UInt8], aad: [UInt8]) {
    self.data = data
    self.aad = aad
  }

  public init(data: String, aad: String) {
    self.data = Array(data.utf8)
    self.aad = Array(aad.utf8)
  }

  init(cstyle: plaintext_t) {
    data = Array(UnsafeBufferPointer(start: cstyle.data, count: cstyle.data_len))
    aad = Array(UnsafeBufferPointer(start: cstyle.aad, count: cstyle.aad_len))
  }

  func getInternal() -> plaintext_t {
    return plaintext_t(data: UnsafePointer(data), data_len: data.count, aad: UnsafePointer(aad), aad_len: aad.count)
  }
}
