//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

import Foundation
import Security
import PeacemakrCoreCrypto_C

// TODO: Handle errors more swifty-ly

public struct RandomDevice {
    var generator: (@convention(c) (Optional<UnsafeMutablePointer<UInt8>>, Int) -> Int32)
    var err: (@convention(c) (Int32) -> Optional<UnsafePointer<CChar>>)
}

public func NewRandomDevice() -> RandomDevice {
    return RandomDevice(
            generator: {(buf: Optional<UnsafeMutablePointer<UInt8>>, num: Int) -> Int32 in
                if buf == nil {
                    return 1
                }
                let status = SecRandomCopyBytes(kSecRandomDefault, num, buf)
                if status != errSecSuccess {
                    return status
                }
                return 0
            },
            err: {(err: Int32) -> Optional<UnsafePointer<CChar>> in
                if err == 1 {
                    return UnsafePointer(("buf was nil").cString(using: .utf8))
                }
                if err == 0 {
                    return nil
                }
                else {
                    return UnsafePointer(("unknown error in SecRandomCopyBytes").cString(using: .utf8))
                }
            }
    )
}

fileprivate func GetRandomDevice(device: RandomDevice) -> UnsafeMutablePointer<random_device_t> {
    var rand = random_device_t(
            generator: device.generator,
            err: device.err
    )
    return UnsafeMutablePointer(&rand)
}

enum EncryptionMode {
    case SYMMETRIC
    case ASYMMETRIC
}

fileprivate func GetEncryptionMode(mode: EncryptionMode) -> encryption_mode {
    switch mode {
    case .SYMMETRIC:
        return encryption_mode(0)
    case .ASYMMETRIC:
        return encryption_mode(1)
    }
}

public enum SymmetricCipher {
    case AES_128_GCM
    case AES_192_GCM
    case AES_256_GCM
    case CHACHA20_POLY1305
}

fileprivate func GetSymmetricCipher(algo: SymmetricCipher) -> symmetric_cipher {
    switch algo {
    case .AES_128_GCM:
        return symmetric_cipher(0)
    case .AES_192_GCM:
        return symmetric_cipher(1)
    case .AES_256_GCM:
        return symmetric_cipher(2)
    case .CHACHA20_POLY1305:
        return symmetric_cipher(3)
    }
}

public enum AsymmetricCipher {
    case NONE
    case RSA_2048
    case RSA_4096
//    case EC25519
}

fileprivate func GetAsymmetricCipher(algo: AsymmetricCipher) -> asymmetric_cipher {
    switch algo {
    case .NONE:
        return asymmetric_cipher(0)
    case .RSA_2048:
        return asymmetric_cipher(1)
    case .RSA_4096:
        return asymmetric_cipher(2)
    }
}

public enum MessageDigestAlgorithm {
    case SHA_224
    case SHA_256
    case SHA_384
    case SHA_512
}

fileprivate func GetMessageDigestAlgorithm(algo: MessageDigestAlgorithm) -> message_digest_algorithm {
    switch algo {
    case .SHA_224:
        return message_digest_algorithm(0)
    case .SHA_256:
        return message_digest_algorithm(1)
    case .SHA_384:
        return message_digest_algorithm(2)
    case .SHA_512:
        return message_digest_algorithm(3)
    }
}

public struct CryptoConfig {
    var encryption_mode: EncryptionMode
    var symmetric_cipher: SymmetricCipher
    var asymmetric_cipher: AsymmetricCipher
    var digest_algorithm: MessageDigestAlgorithm
}

fileprivate func GetCryptoConfig(config: CryptoConfig) -> crypto_config_t {
    return crypto_config_t(
            mode: GetEncryptionMode(mode: config.encryption_mode),
            symm_cipher: GetSymmetricCipher(algo: config.symmetric_cipher),
            asymm_cipher: GetAsymmetricCipher(algo: config.asymmetric_cipher),
            digest_algorithm: GetMessageDigestAlgorithm(algo: config.digest_algorithm)
    )
}

public struct Plaintext {
    var data: [UInt8]
    var aad: [UInt8]
}

fileprivate func GetPlaintext(plain: Plaintext) -> plaintext_t {
    return plaintext_t(
            data: UnsafePointer<UInt8>(plain.data),
            data_len: plain.data.count,
            aad: UnsafePointer<UInt8>(plain.aad),
            aad_len: plain.aad.count
    )
}

fileprivate func SetPlaintext(plain: plaintext_t) -> Plaintext {
    return Plaintext(
            data: Array(UnsafeBufferPointer(start: plain.data, count: plain.data_len)),
            aad: Array(UnsafeBufferPointer(start: plain.aad, count: plain.aad_len))
    )
}

public struct CiphertextBlob {
    var blob: OpaquePointer
}

public class PeacemakrKey {
    var key: OpaquePointer
    init(config: CryptoConfig, rand: RandomDevice) {
        self.key = PeacemakrKey_new(GetCryptoConfig(config: config), GetRandomDevice(device: rand))
    }
    init(config: CryptoConfig, bytes: UnsafePointer<UInt8>) {
        self.key = PeacemakrKey_new_bytes(GetCryptoConfig(config: config), bytes)
    }
    deinit {
        PeacemakrKey_free(self.key)
    }
}

public func Encrypt(config: CryptoConfig, key: PeacemakrKey, plaintext: Plaintext, rand: RandomDevice) -> CiphertextBlob {
    var p = GetPlaintext(plain: plaintext)
    return CiphertextBlob(
            blob: peacemakr_encrypt(
                    GetCryptoConfig(config: config),
                    key.key,
                    &p,
                    GetRandomDevice(device: rand)
            )
    )
}

public func Decrypt(key: PeacemakrKey, ciphertext: CiphertextBlob) -> (Plaintext, Bool) {
    var plaintext = plaintext_t(data: "", data_len: 0, aad: "", aad_len: 0)

    let success = peacemakr_decrypt(key.key, ciphertext.blob, &plaintext)
    return (SetPlaintext(plain: plaintext), success)
}

public func Serialize(ciphertext: CiphertextBlob) -> [UInt8] {
    var out_size = 0
    let serialized = serialize_blob(ciphertext.blob, UnsafeMutablePointer<Int>(&out_size))
    let out = UnsafeBufferPointer(start: serialized, count: out_size)
    return Array(out)
}

public func Deserialize(serialized: [UInt8]) -> CiphertextBlob {
    return CiphertextBlob(blob: deserialize_blob(UnsafePointer<UInt8>(serialized), serialized.count))
}

