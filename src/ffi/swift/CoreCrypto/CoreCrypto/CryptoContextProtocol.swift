//
//  CryptoContextProtocol.swift
//  CoreCrypto
//
//  Created by Yuliia Synytsia on 5/19/19.
//  Copyright © 2019 Peacemakr. All rights reserved.
//

import Foundation

/// CoreCrypto Swift API
public protocol CryptoContextProtocol {
  
  /// MARK: - Initialization
  
  /// Should be called once on startup. Ensures that the system's random number
  /// generator is well seeded and any numbers generated have sufficient entropy.
  ///
  /// - Returns: boolean indicator of system's random number genearator readiness
  static func setup() -> Bool
  
  /// MARK: - Encryption and Decryption
  
  ///Performs the encryption operation.
  ///
  /// - Parameters:
  ///     - recipientKey: symmetric or asymmetric key
  ///     - plaintext: plain text to encrypt
  ///     - rand: uses to generate the IV/nonce
  /// - Returns: ciphertext blob on success, else returns a non-nil error.
  static func encrypt(recipientKey: PeacemakrKey, plaintext: Plaintext, rand: RandomDevice) -> Result<Ciphertext>
  
  ///Performs the decryption operation.
  ///
  /// - Parameters:
  ///     - recipientKey: symmetric or asymmetric key
  ///     - ciphertext: plain text to encrypt
  /// - Returns: decrypted message Plaintext on success, else returns a non-nil error.
  static func decrypt(recipientKey: PeacemakrKey, ciphertext: Ciphertext) -> Result<(Plaintext, Bool)>

  
  /// MARK: - Signing
  
  /// Signs the plaintext
  ///
  /// - Parameters:
  ///     - recipientKey: symmetric or asymmetric key
  ///     - plaintext: Plaintext to sign
  ///     - digest: the OpenSSL digest algorithm
  ///     - ciphertext: mutable signed message Ciphertext
  static func sign(recipientKey: PeacemakrKey, plaintext: Plaintext, digest: MessageDigestAlgorithm, ciphertext: inout Ciphertext) -> Void
  
  
  ///MARK: - Data serialization and deserialization
  
  ///  Serializes encrypted message.
  ///
  /// - Parameters:
  ///     - digest: the OpenSSL digest algorithm
  ///     - ciphertext_blob: encrypted message as a Ciphertext
  /// - Returns: Base64 encoded buffer on success, else returns a non-nil error.
  static func serialize(_ digest: MessageDigestAlgorithm, _ ciphertext_blob: Ciphertext) -> Result<Data>
  
  ///  Deserializes encrypted message.
  ///
  /// - Parameter serialized: Base64 encoded data message
  /// - Returns: Base64 encoded buffer on success, else returns a non-nil error.
  static func deserialize(_ serialized: Data) -> Result<(Ciphertext, CryptoConfig)>
  
  /// MARK: - Verification
  
  /// Verifies the plaintext
  ///
  /// - Parameters:
  ///     - senderKey: symmetric or asymmetric key
  ///     - plaintext: Plaintext to verify
  ///     - digest: the OpenSSL digest algorithm
  ///     - ciphertext: mutable signed message Ciphertext
  /// - Returns: false if verification is unsuccessful and a non-nil error.
  static func verify(senderKey: PeacemakrKey, plaintext: Plaintext, ciphertext: inout Ciphertext) -> Result<Bool>
  
  /// Attempts to extract any AAD from the message.
  /// Note that this AAD is unconfirmed and may have been tampered with.
  ///
  /// - Parameter serialized: data
  /// - Returns: plaintext on success or non-nil error
  static func extractUnverifiedAAD(_ serialized: Data) -> Result<Plaintext>

  
  /// Computes the HMAC. Allocates memory and
  /// returns it to the caller with the HMAC stored inside.
  ///
  /// - Parameters:
  ///     - digestAlgorithm: the OpenSSL digest algorithm
  ///     - key: symmetric or asymmetric key
  ///     - buf: data
  /// - Returns: data with the HMAC stored inside on success or non-nil error
  static func HMAC(digestAlgorithm: MessageDigestAlgorithm, key: PeacemakrKey, buf: Data) -> Result<Data>
  
}





