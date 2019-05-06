//
// Created by Aman LaChapelle on 11/2/18.
//

import Foundation
import libCoreCrypto

/**
 Thin Swift wrapper around the peacemakr C type plaintext_t. Uses
 Arrays of UInt8 to match as closely as possible while still staying
 in Swift-land.
 */
public class Plaintext {
  private let data: Data
  private let aad: Data

  public init(data: Data, aad: Data) {
    self.data = data
    self.aad = aad
  }

  public init?(data: String, aad: String) {
    guard let dataD = data.data(using: .utf8),
      let aadD = aad.data(using: .utf8) else {
      return nil
    }
    
    self.data = dataD
    self.aad = aadD
  }
  
  public var encryptableData: Data {
    return self.data
  }
  
  public var authenticatableData: Data {
    return self.aad
  }

  init(cstyle: plaintext_t) {
    data = Data(buffer: UnsafeBufferPointer(start: cstyle.data, count: cstyle.data_len))
    aad = Data(buffer: UnsafeBufferPointer(start: cstyle.aad, count: cstyle.aad_len))
  }

  func getInternal() -> plaintext_t {
    let dataPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: self.data.count)
    let aadPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: self.aad.count)
    
    self.data.copyBytes(to: dataPtr, count: self.data.count)
    self.aad.copyBytes(to: aadPtr, count: self.aad.count)
    
    return plaintext_t(data: dataPtr, data_len: self.data.count, aad: aadPtr, aad_len: self.aad.count)
  }
}

func destroyPlaintext(cstyle: plaintext_t) {
  cstyle.data.deallocate()
  cstyle.aad.deallocate()
}
