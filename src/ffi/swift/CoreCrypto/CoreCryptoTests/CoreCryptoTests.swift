//
//  CoreCryptoTests.swift
//  CoreCryptoTests
//
//  Created by Aman LaChapelle on 11/2/18.
//  Copyright © 2018 Peacemakr. All rights reserved.
//

import XCTest
@testable import CoreCrypto

class CoreCryptoTests: XCTestCase {

  override func setUp() {
  }

  override func tearDown() {
  }

  func innerTest(mode: EncryptionMode, symm_cipher: SymmetricCipher, asymm_cipher: AsymmetricCipher, digest: MessageDigestAlgorithm) {
    let cfg = CryptoConfig(mode: mode, symm_cipher: symm_cipher, asymm_cipher: asymm_cipher, digest: digest)
    let device = DefaultRandomDevice()

    let plaintextIn = Plaintext(data: "Hello from swift!", aad: "And I'm AAD")
    let context = try? CryptoContext()
    let key = try? PeacemakrKey(config: cfg, rand: device)
    XCTAssert(context != nil && key != nil, "Setup failed")
    
    let encrypted = try? context!.Encrypt(key: key!, plaintext: plaintextIn, rand: device)
    XCTAssert(encrypted != nil, "Something failed in Encryption")
    let unverfiedAAD = try? context!.ExtractUnverifiedAAD(serialized: encrypted!)
    XCTAssert(unverfiedAAD!.aad == plaintextIn.aad, "Something failed in ExtractUnverfiedAAD")
    let decrypted = try? context!.Decrypt(key: key!, serialized: encrypted!)
    XCTAssert(decrypted != nil, "Something failed in Decryption")
    XCTAssert(decrypted!.data == plaintextIn.data)
    XCTAssert(decrypted!.aad == plaintextIn.aad)
    
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
