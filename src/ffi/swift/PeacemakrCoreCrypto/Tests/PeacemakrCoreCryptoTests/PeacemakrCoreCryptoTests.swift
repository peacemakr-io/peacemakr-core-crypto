import XCTest
@testable import PeacemakrCoreCrypto

func randomAlphaNumericString(length: Int) -> String {
    let allowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    let allowedCharsCount = UInt32(allowedChars.count)
    var randomString = ""

    for _ in 0..<length {
        let randomNum = Int(arc4random_uniform(allowedCharsCount))
        let randomIndex = allowedChars.index(allowedChars.startIndex, offsetBy: randomNum)
        let newCharacter = allowedChars[randomIndex]
        randomString += String(newCharacter)
    }

    return randomString
}

func random(_ n:Int) -> Int
{
    return Int(arc4random_uniform(UInt32(n)))
}

final class PeacemakrCoreCryptoTests: XCTestCase {
    func testSymmetricEncrypt() {
        for cipher in SymmetricCipher.AllValues {
            let cfg = CryptoConfig(
                    encryption_mode: EncryptionMode.SYMMETRIC,
                    symmetric_cipher: cipher,
                    asymmetric_cipher: AsymmetricCipher.NONE,
                    digest_algorithm: MessageDigestAlgorithm.SHA_512
            )

            let plaintextIn = Plaintext(
                    data: Array(randomAlphaNumericString(length: random(100000)).utf8),
                    aad:  Array(randomAlphaNumericString(length: random(100000)).utf8)
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
    }

    func testAsymmetricEncrypt() {
        for asymm in AsymmetricCipher.AllValues {
            for cipher in SymmetricCipher.AllValues {
                let cfg = CryptoConfig(
                        encryption_mode: EncryptionMode.ASYMMETRIC,
                        symmetric_cipher: cipher,
                        asymmetric_cipher: asymm,
                        digest_algorithm: MessageDigestAlgorithm.SHA_512
                )

                let plaintextIn = Plaintext(
                        data: Array(randomAlphaNumericString(length: random(100000)).utf8),
                        aad:  Array(randomAlphaNumericString(length: random(100000)).utf8)
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
        }
    }

    func testSerialize() {
        for digest_algo in MessageDigestAlgorithm.AllValues {
            for asymm in AsymmetricCipher.AllValues {
                for cipher in SymmetricCipher.AllValues {
                    let cfg = CryptoConfig(
                            encryption_mode: EncryptionMode.ASYMMETRIC,
                            symmetric_cipher: cipher,
                            asymmetric_cipher: asymm,
                            digest_algorithm: digest_algo
                    )

                    let plaintextIn = Plaintext(
                            data: Array(randomAlphaNumericString(length: random(100000)).utf8),
                            aad:  Array(randomAlphaNumericString(length: random(100000)).utf8)
                    )

                    var randDevice = NewRandomDevice()

                    let key = PeacemakrKey(config: cfg, rand: &randDevice)

                    let ciphertext = Encrypt(config: cfg, key: key, plaintext: plaintextIn, rand: &randDevice)
                    XCTAssertNotNil(ciphertext.blob)

                    let serialized = Serialize(ciphertext: ciphertext)

                    let deserializedCiphertext = Deserialize(serialized: serialized)

                    let (plaintextOut, success) = Decrypt(key: key, ciphertext: deserializedCiphertext)
                    XCTAssertTrue(success)

                    XCTAssertEqual(plaintextIn.data, plaintextOut.data)
                    XCTAssertEqual(plaintextIn.aad, plaintextOut.aad)
                }
            }
        }
    }

    static var allTests = [
        ("testSymmetricEncrypt", testSymmetricEncrypt),
        ("testAsymmetricEncrypt", testAsymmetricEncrypt),
        ("testSerialize", testSerialize)
    ]
}
