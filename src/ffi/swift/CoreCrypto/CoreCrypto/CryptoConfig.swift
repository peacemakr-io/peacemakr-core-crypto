//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

import Foundation

import libCoreCrypto

/**
 Configures the encryption mode for the Peacemakr CoreCrypto library. Selects
 Symmetric key or Asymmetric key cryptography.
 */
public enum EncryptionMode: UInt32, CaseIterable {
  case SYMMETRIC = 0
  case ASYMMETRIC = 1
}

/**
 The Peacemakr library encrypts messages in 2 modes:
 (1) Symmetric cryptography, in which case this enum chooses
     the cipher to use
 (2) Asymmetric cryptography, in which case the public key will
     be used to encrypt a symmetric key (this enum chooses the
     algorithm) that will encrypt the message for performance
     reasons.
 */
public enum SymmetricCipher: UInt32, CaseIterable {
  case AES_128_GCM = 0
  case AES_192_GCM = 1
  case AES_256_GCM = 2
  case CHACHA20_POLY1305 = 3
}

/**
 This enum selects the Asymmetric crypto algorithm to use
 for a given cryptographic operation.
 NONE is appropriate when the EncryptionMode is SYMMETRIC.
 */
public enum AsymmetricCipher: UInt32, CaseIterable {
  case NONE = 0, RSA_2048 = 1, RSA_4096 = 2
}

/**
 The Peacemakr CoreCrypto library will digest a serialized
 message to prevent tampering and errors due to corruption.
 This enum selects the hash function that will be used.
 */
public enum MessageDigestAlgorithm: UInt32, CaseIterable {
  case SHA_224 = 0
  case SHA_256 = 1
  case SHA_384 = 2
  case SHA_512 = 3
  case SHA3_224 = 4
  case SHA3_256 = 5
  case SHA3_384 = 6
  case SHA3_512 = 7
}

public class CryptoConfig: Equatable {
  let internalRepr: crypto_config_t

  init(cfg: crypto_config_t) {
    internalRepr = cfg
  }

  public init(mode: EncryptionMode, symm_cipher: SymmetricCipher, asymm_cipher: AsymmetricCipher, digest: MessageDigestAlgorithm) {
    internalRepr = crypto_config_t(
        mode: encryption_mode(mode.rawValue),
        symm_cipher: symmetric_cipher(symm_cipher.rawValue),
        asymm_cipher: asymmetric_cipher(asymm_cipher.rawValue),
        digest_algorithm: message_digest_algorithm(digest.rawValue)
    )
  }

  public var Mode: EncryptionMode {
    return EncryptionMode(rawValue: internalRepr.mode.rawValue)!
  }

  public var SymmCipher: SymmetricCipher {
    return SymmetricCipher(rawValue: internalRepr.symm_cipher.rawValue)!
  }

  public var AsymmCipher: AsymmetricCipher {
    return AsymmetricCipher(rawValue: internalRepr.asymm_cipher.rawValue)!
  }

  public var DigestAlgorithm: MessageDigestAlgorithm {
    return MessageDigestAlgorithm(rawValue: internalRepr.digest_algorithm.rawValue)!
  }

  func getInternal() -> crypto_config_t {
    return internalRepr
  }
  
  public static func == (lhs: CryptoConfig, rhs: CryptoConfig) -> Bool {
    return (lhs.Mode == rhs.Mode) &&
           (lhs.SymmCipher == rhs.SymmCipher) &&
           (lhs.AsymmCipher == rhs.AsymmCipher) &&
           (lhs.DigestAlgorithm == rhs.DigestAlgorithm)
  }
}
