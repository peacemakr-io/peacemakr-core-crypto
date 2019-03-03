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
    let dataD = data.data(using: .utf8)
    let aadD = aad.data(using: .utf8)
    
    if dataD == nil || aadD == nil {
      return nil
    }
    
    self.data = dataD!
    self.aad = aadD!
  }
  
  public var EncryptableData: Data {
    return self.data
  }
  
  public var AuthenticatableData: Data {
    return self.aad
  }

  init(cstyle: plaintext_t) {
    data = Data(buffer: UnsafeBufferPointer(start: cstyle.data, count: cstyle.data_len))
    aad = Data(buffer: UnsafeBufferPointer(start: cstyle.aad, count: cstyle.aad_len))
  }

  func getInternal() -> plaintext_t {
    return self.data.withUnsafeBytes { (dataBytes: UnsafePointer<UInt8>) -> plaintext_t in
      self.aad.withUnsafeBytes { (aadBytes: UnsafePointer<UInt8>) -> plaintext_t in
        return plaintext_t(data: dataBytes, data_len: self.data.count, aad: aadBytes, aad_len: self.aad.count)
      }
    }
  }
}
