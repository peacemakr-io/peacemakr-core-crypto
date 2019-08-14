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

    let plaintextIn = Plaintext(data: "Hello from swift!", aad: "And I'm AAD")!
    
    var key: PeacemakrKey? = nil
    
    let firstKey = (mode == EncryptionMode.ASYMMETRIC) ? PeacemakrKey(asymmCipher: asymm_cipher, symmCipher: symm_cipher, rand: device)! : PeacemakrKey(symmCipher: symm_cipher, rand: device)!
    
    if asymm_cipher.rawValue >= AsymmetricCipher.ECDH_P256.rawValue {
      let secondKey = PeacemakrKey(asymmCipher: asymm_cipher, symmCipher: symm_cipher, rand: device)!
      key = PeacemakrKey(symmCipher: symm_cipher, myKey: firstKey, peerKey: secondKey)
    } else {
      key = firstKey
    }

    // TODO: doesn't work for ECDH yet
    var encrypted = UnwrapCall(CryptoContext.encrypt(recipientKey: key!, plaintext: plaintextIn, rand: device), onError: assertFalse)!
    
    CryptoContext.sign(senderKey: key!, plaintext: plaintextIn, digest: digest, ciphertext: &(encrypted))
    let serialized = UnwrapCall(CryptoContext.serialize(digest, encrypted), onError: assertFalse)!
    
    let unverfiedAAD = UnwrapCall(CryptoContext.extractUnverifiedAAD(serialized), onError: assertFalse)!
    
    XCTAssert(unverfiedAAD.authenticatableData == plaintextIn.authenticatableData, "Something failed in ExtractUnverfiedAAD")

    var (deserialized, outCfg) = UnwrapCall(CryptoContext.deserialize(serialized), onError: assertFalse)!
    
    // The asymmetric ciphers may not match if it's ECDH, and the modes won't either, and that's OK
    // Mostly because the mode is technically SYMMETRIC for ECDH-based crypto, and the asymmetric algorithm
    // won't be set for the generated key
    XCTAssert(cfg.symmCipher == outCfg.symmCipher && cfg.digestAlgorithm == outCfg.digestAlgorithm)
    let (decrypted, needVerify) = UnwrapCall(CryptoContext.decrypt(recipientKey: key!, ciphertext: deserialized), onError: assertFalse)!
    
    
    if needVerify {
      let success = UnwrapCall(CryptoContext.verify(senderKey: key!, plaintext: decrypted, ciphertext: &(deserialized)), onError: assertFalse)!
      XCTAssert(success, "Verification failed")
    }
    XCTAssert(decrypted.encryptableData == plaintextIn.encryptableData)
    XCTAssert(decrypted.authenticatableData == plaintextIn.authenticatableData)
    
  }

  func testSymmetric() {
    for symmCipher in SymmetricCipher.allCases {
      if symmCipher == SymmetricCipher.SYMMETRIC_UNSPECIFIED {
        continue
      }
      for digestAlgo in MessageDigestAlgorithm.allCases {
        if digestAlgo == MessageDigestAlgorithm.DIGEST_UNSPECIFIED {
          continue
        }
        innerTest(mode: EncryptionMode.SYMMETRIC, symm_cipher: symmCipher, asymm_cipher: AsymmetricCipher.ASYMMETRIC_UNSPECIFIED, digest: digestAlgo)
      }
    }
  }

  func testAsymmetric() {
    for asymmCipher in AsymmetricCipher.allCases {
      if asymmCipher == AsymmetricCipher.ASYMMETRIC_UNSPECIFIED {
        continue
      }
      for symmCipher in SymmetricCipher.allCases {
        if symmCipher == SymmetricCipher.SYMMETRIC_UNSPECIFIED {
          continue
        }
        for digestAlgo in MessageDigestAlgorithm.allCases {
          if digestAlgo == MessageDigestAlgorithm.DIGEST_UNSPECIFIED {
            continue
          }
          innerTest(mode: EncryptionMode.ASYMMETRIC, symm_cipher: symmCipher, asymm_cipher: asymmCipher, digest: digestAlgo)
        }
      }
    }
  }

}
