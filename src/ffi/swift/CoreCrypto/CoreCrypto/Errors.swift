//
//  Errors.swift
//  CoreCrypto
//
//  Created by Aman LaChapelle on 12/27/18.
//  Copyright © 2018 Peacemakr. All rights reserved.
//

import Foundation

public enum Result<T> {
  case result (T)
  case error (CoreCryptoError)
}

public enum CoreCryptoError: LocalizedError {
  case initializationFailed
  case encryptionFailed
  case serializationFailed
  case deserializationFailed
  case decryptionFailed
  case verificationFailed
  case HMACFailed
  case keyAllocationFailed
  case keySerializationFailed
  
  public var errorDescription: String? {
    switch self {
    case .initializationFailed:
      return "Library initialization failed"
    case .encryptionFailed:
      return "Encryption failed"
    case .serializationFailed:
      return "Serialization failed"
    case .deserializationFailed:
      return "Deserialization failed"
    case .decryptionFailed:
      return "Decryption failed"
    case .verificationFailed:
      return "Verification failed"
    case .HMACFailed:
      return "HMAC failed"
    case .keyAllocationFailed:
      return "Key allocation failed"
    case .keySerializationFailed:
      return "Key serialization failed"
    }
  }
}

public func UnwrapCall<T>(_ r: Result<T>, onError: ((String) -> Void)) -> T? {
  switch r {
  case let .error(err):
    onError(err.localizedDescription)
    return nil
  case let .result(retval):
    return retval
  }
}

public func UnwrapCall<T>(_ r: Result<T>) throws -> T {
  switch r {
  case let .error(err):
    throw err
  case let .result(retval):
    return retval
  }
}

