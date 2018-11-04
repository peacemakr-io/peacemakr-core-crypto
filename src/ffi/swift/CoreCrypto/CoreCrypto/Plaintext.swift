//
// Created by Aman LaChapelle on 11/2/18.
//

import Foundation
import libCoreCrypto

public class Plaintext {
  private let data: [UInt8]
  private let aad: [UInt8]

  public init(data: [UInt8], aad: [UInt8]) {
    self.data = data
    self.aad = aad
  }

  public init(data: String, aad: String) {
    self.data = Array(data.utf8)
    self.aad = Array(aad.utf8)
  }
  
  public var Data: [UInt8] {
    return self.data
  }
  
  public var AAD: [UInt8] {
    return self.aad
  }

  init(cstyle: plaintext_t) {
    data = Array(UnsafeBufferPointer(start: cstyle.data, count: cstyle.data_len))
    aad = Array(UnsafeBufferPointer(start: cstyle.aad, count: cstyle.aad_len))
  }

  func getInternal() -> plaintext_t {
    return plaintext_t(data: UnsafePointer(data), data_len: data.count, aad: UnsafePointer(aad), aad_len: aad.count)
  }
}
