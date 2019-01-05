//
//  CoreCryptoTests.swift
//  CoreCryptoTests
//
//  Created by Aman LaChapelle on 11/2/18.
//  Copyright © 2018 Peacemakr. All rights reserved.
//

import XCTest
@testable import CoreCrypto

fileprivate func assertFalse(_ s: String) -> Void {
  XCTAssert(false, s)
}

class CoreCryptoTests: XCTestCase {

  override func setUp() {
  }

  override func tearDown() {
  }

  func innerTest(mode: EncryptionMode, symm_cipher: SymmetricCipher, asymm_cipher: AsymmetricCipher, digest: MessageDigestAlgorithm) {
    let cfg = CryptoConfig(mode: mode, symm_cipher: symm_cipher, asymm_cipher: asymm_cipher, digest: digest)
    let device = DefaultRandomDevice()

    let plaintextIn = Plaintext(data: "Hello from swift!", aad: "And I'm AAD")
    let context = CryptoContext()!
    let key = PeacemakrKey(config: cfg, rand: device)!

    var encrypted = UnwrapCall(context.Encrypt(key: key, plaintext: plaintextIn, rand: device), onError: assertFalse)!
    
    context.Sign(senderKey: key, plaintext: plaintextIn, ciphertext: &(encrypted))
    let serialized = UnwrapCall(context.Serialize(encrypted), onError: assertFalse)!
    
    let unverfiedAAD = UnwrapCall(context.ExtractUnverifiedAAD(serialized), onError: assertFalse)!
    
    XCTAssert(unverfiedAAD.AuthenticatableData == plaintextIn.AuthenticatableData, "Something failed in ExtractUnverfiedAAD")

    var (deserialized, outCfg) = UnwrapCall(context.Deserialize(serialized), onError: assertFalse)!
    
    XCTAssert(cfg == outCfg)
    let (decrypted, needVerify) = UnwrapCall(context.Decrypt(key: key, ciphertext: deserialized), onError: assertFalse)!
    
    
    if needVerify {
      let success = UnwrapCall(context.Verify(senderKey: key, plaintext: decrypted, ciphertext: &(deserialized)), onError: assertFalse)!
      XCTAssert(success, "Verification failed")
    }
    XCTAssert(decrypted.EncryptableData == plaintextIn.EncryptableData)
    XCTAssert(decrypted.AuthenticatableData == plaintextIn.AuthenticatableData)
    
  }

  func testSymmetric() {
    for symmCipher in SymmetricCipher.allCases {
      for digestAlgo in MessageDigestAlgorithm.allCases {
        innerTest(mode: EncryptionMode.SYMMETRIC, symm_cipher: symmCipher, asymm_cipher: AsymmetricCipher.NONE, digest: digestAlgo)
      }
    }
  }

  func testAsymmetric() {
    for asymmCipher in AsymmetricCipher.allCases {
      if asymmCipher == AsymmetricCipher.NONE {
        continue
      }
      for symmCipher in SymmetricCipher.allCases {
        for digestAlgo in MessageDigestAlgorithm.allCases {
          innerTest(mode: EncryptionMode.ASYMMETRIC, symm_cipher: symmCipher, asymm_cipher: asymmCipher, digest: digestAlgo)
        }
      }
    }
  }

}
