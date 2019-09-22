import random
import string
import unittest
import peacemakr_core_crypto_python as p


def get_random_data():
    length = random.randint(0, 1000)
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))


class TestCoreCrypto(unittest.TestCase):
    def test_symmetric(self):
        rand = p.RandomDevice()
        context = p.CryptoContext()

        for cipher in p.SymmetricCipher.__members__:
            if cipher == "UNSPECIFIED":
                continue

            plaintext = p.Plaintext(get_random_data(), get_random_data())

            key = p.Key(p.SymmetricCipher.__members__[cipher], rand)

            encrypted = context.encrypt(key, plaintext, rand)
            context.sign(key, plaintext, p.DigestAlgorithm.SHA_256, encrypted)
            serialized = context.serialize(p.DigestAlgorithm.SHA_256, encrypted)
            self.assertNotEqual(serialized, plaintext.data)

            deserialized = context.deserialize(serialized)

            # Assert the configs coming out are equal
            self.assertEqual(key.get_config().mode, deserialized[1].mode)
            self.assertEqual(key.get_config().symm_cipher, deserialized[1].symm_cipher)
            self.assertEqual(key.get_config().asymm_cipher, deserialized[1].asymm_cipher)
            # These won't be equal because the original key didn't have the digest algorithm set
            self.assertNotEqual(key.get_config().digest_algorithm, deserialized[1].digest_algorithm)

            # Do the decrypt
            result = context.decrypt(key, deserialized[0])
            self.assertTrue(result[1])
            self.assertEqual(result[0].data, plaintext.data)
            # Verify
            verified = context.verify(key, result[0], deserialized[0])
            self.assertTrue(verified)

    def test_asymmetric(self):
        rand = p.RandomDevice()
        context = p.CryptoContext()

        for cipher in p.AsymmetricCipher.__members__:
            if cipher == "UNSPECIFIED":
                continue

            for symmCipher in p.SymmetricCipher.__members__:
                if symmCipher == "UNSPECIFIED":
                    continue

                plaintext = p.Plaintext(get_random_data(), get_random_data())
                key = p.Key(p.AsymmetricCipher.__members__[cipher], p.SymmetricCipher.__members__[symmCipher], rand)

                if cipher[:4] == "ECDH":
                    myKey = p.Key(p.AsymmetricCipher.__members__[cipher], p.SymmetricCipher.__members__[symmCipher], rand)
                    peerKey = p.Key(p.AsymmetricCipher.__members__[cipher], p.SymmetricCipher.__members__[symmCipher], rand)
                    key = p.Key(p.SymmetricCipher.__members__[symmCipher], myKey, peerKey)

                encrypted = context.encrypt(key, plaintext, rand)
                context.sign(key, plaintext, p.DigestAlgorithm.SHA_256, encrypted)
                serialized = context.serialize(p.DigestAlgorithm.SHA_256, encrypted)
                self.assertNotEqual(serialized, plaintext.data)

                deserialized = context.deserialize(serialized)

                # Assert the configs coming out are equal
                self.assertEqual(key.get_config().mode, deserialized[1].mode)
                self.assertEqual(key.get_config().symm_cipher, deserialized[1].symm_cipher)
                self.assertEqual(key.get_config().asymm_cipher, deserialized[1].asymm_cipher)
                # These won't be equal because the original key didn't have the digest algorithm set
                self.assertNotEqual(key.get_config().digest_algorithm, deserialized[1].digest_algorithm)

                # Do the decrypt
                result = context.decrypt(key, deserialized[0])
                self.assertTrue(result[1])
                self.assertEqual(result[0].data, plaintext.data)
                # Verify
                verified = context.verify(key, result[0], deserialized[0])
                self.assertTrue(verified)


if __name__ == '__main__':
    unittest.main()