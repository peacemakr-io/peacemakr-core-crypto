import XCTest
@testable import PeacemakrCoreCrypto

final class PeacemakrCoreCryptoTests: XCTestCase {
    func testSymmetricEncrypt() {
        let cfg = CryptoConfig(
                encryption_mode: EncryptionMode.SYMMETRIC,
                symmetric_cipher: SymmetricCipher.CHACHA20_POLY1305,
                asymmetric_cipher: AsymmetricCipher.NONE,
                digest_algorithm: MessageDigestAlgorithm.SHA_512
        )

        let plaintextIn = Plaintext(
                data: Array("Hello world, I'm testing encryption from swift!".utf8),
                aad:  Array("And I'm AAD from swift".utf8)
        )

        var randDevice = NewRandomDevice()

        let key = PeacemakrKey(config: cfg, rand: &randDevice)

        let ciphertext = Encrypt(config: cfg, key: key, plaintext: plaintextIn, rand: &randDevice)
        XCTAssertNotNil(ciphertext.blob)

        let (plaintextOut, success) = Decrypt(key: key, ciphertext: ciphertext)
        XCTAssertTrue(success)

        XCTAssertEqual(plaintextIn.data, plaintextOut.data)
        XCTAssertEqual(plaintextIn.aad, plaintextOut.aad)
    }

//    func testAsymmetricEncrypt() {
//        for asymm in AsymmetricCipher {
//
//            if asymm == AsymmetricCipher.NONE {
//                continue
//            }
//
//            for cipher in SymmetricCipher {
//                let cfg = CryptoConfig(
//                        encryption_mode: EncryptionMode.ASYMMETRIC,
//                        symmetric_cipher: cipher,
//                        asymmetric_cipher: asymm,
//                        digest_algorithm: MessageDigestAlgorithm.SHA_512
//                )
//
//                let plaintextIn = Plaintext(
//                        data: "Hello world, I'm testing encryption from swift!",
//                        aad:  "And I'm AAD from go"
//                )
//
//                var randDevice = NewRandomDevice()
//
//                let key = PeacemakrKey(config: cfg, rand: randDevice)
//
//                let ciphertext = Encrypt(config: cfg, key: key, plaintext: plaintextIn, rand: randDevice)
//                XCTAssertNotNil(ciphertext.blob)
//
//                let plaintextOut = Decrypt(key: key, ciphertext: ciphertext)
//
//                XCTAssertEqual(plaintextIn.data, plaintextOut.data)
//                XCTAssertEqual(plaintextIn.aad, plaintextOut.aad)
//            }
//        }
//    }
//
//    func testSerialize() {
//        for digest_algo in MessageDigestAlgorithm {
//            for asymm in AsymmetricCipher {
//
//                if asymm == AsymmetricCipher.NONE {
//                    continue
//                }
//
//                for cipher in SymmetricCipher {
//                    let cfg = CryptoConfig(
//                            encryption_mode: EncryptionMode.ASYMMETRIC,
//                            symmetric_cipher: cipher,
//                            asymmetric_cipher: asymm,
//                            digest_algorithm: digest_algo
//                    )
//
//                    let plaintextIn = Plaintext(
//                            data: "Hello world, I'm testing encryption from swift!",
//                            aad:  "And I'm AAD from go"
//                    )
//
//                    var randDevice = NewRandomDevice()
//
//                    let key = PeacemakrKey(config: cfg, rand: randDevice)
//
//                    let ciphertext = Encrypt(config: cfg, key: key, plaintext: plaintextIn, rand: randDevice)
//                    XCTAssertNotNil(ciphertext.blob)
//
//                    let serialized = Serialize(ciphertext: ciphertext)
//
//                    let deserializedCiphertext = Deserialize(serialized: serialized)
//
//                    let plaintextOut = Decrypt(key: key, ciphertext: deserializedCiphertext)
//
//                    XCTAssertEqual(plaintextIn.data, plaintextOut.data)
//                    XCTAssertEqual(plaintextIn.aad, plaintextOut.aad)
//                }
//            }
//        }
//    }

    static var allTests = [
        ("testSymmetricEncrypt", testSymmetricEncrypt),
//        ("testAsymmetricEncrypt", testAsymmetricEncrypt),
//        ("testSerialize", testSerialize)
    ]
}
