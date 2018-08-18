package peacemakr_core_crypto

import (
	"bytes"
	"testing"
)

func TestAsymmetricEncrypt(t *testing.T) {
	for i := RSA_2048; i <= RSA_4096; i++ {
		for j := AES_128_GCM; j <= CHACHA20_POLY1305; j++ {
			cfg := CryptoConfig{
				mode:             ASYMMETRIC,
				asymmetricCipher: i,
				symmetricCipher:  j,
				digestAlgorithm:  SHA_512,
			}

			plaintextIn := Plaintext{
				data: []byte("Hello world, I'm testing encryption from go!"),
				aad:  []byte("And I'm AAD from go"),
			}

			randomDevice := NewRandomDevice()

			key := NewPeacemakrKey(cfg, randomDevice)

			ciphertext := Encrypt(cfg, key, plaintextIn, randomDevice)

			plaintextOut, success := Decrypt(key, ciphertext)
			if !success {
				t.Fatalf("Decrypt failed")
			}

			if !bytes.Equal(plaintextIn.data, plaintextOut.data) {
				t.Fatalf("plaintext data did not match")
			}

			if !bytes.Equal(plaintextIn.aad, plaintextOut.aad) {
				t.Fatalf("plaintext data did not match")
			}
		}
	}
}

func TestSymmetricEncrypt(t *testing.T) {
	for j := AES_128_GCM; j <= CHACHA20_POLY1305; j++ {
		cfg := CryptoConfig{
			mode:             SYMMETRIC,
			asymmetricCipher: NONE,
			symmetricCipher:  j,
			digestAlgorithm:  SHA_512,
		}

		plaintextIn := Plaintext{
			data: []byte("Hello world, I'm testing encryption from go!"),
			aad:  []byte("And I'm AAD from go"),
		}

		randomDevice := NewRandomDevice()

		key := NewPeacemakrKey(cfg, randomDevice)

		ciphertext := Encrypt(cfg, key, plaintextIn, randomDevice)

		plaintextOut, success := Decrypt(key, ciphertext)
		if !success {
			t.Fatalf("Decrypt failed")
		}

		if !bytes.Equal(plaintextIn.data, plaintextOut.data) {
			t.Fatalf("plaintext data did not match")
		}

		if !bytes.Equal(plaintextIn.aad, plaintextOut.aad) {
			t.Fatalf("plaintext data did not match")
		}
	}
}

func TestSerialize(t *testing.T) {
	for i := RSA_2048; i <= RSA_4096; i++ {
		for j := AES_128_GCM; j <= CHACHA20_POLY1305; j++ {
			for k := SHA_224; k <= SHA_512; k++ {
				cfg := CryptoConfig{
					mode:             ASYMMETRIC,
					asymmetricCipher: i,
					symmetricCipher:  j,
					digestAlgorithm:  k,
				}

				plaintextIn := Plaintext{
					data: []byte("Hello world, I'm testing encryption from go!"),
					aad:  []byte("And I'm AAD from go"),
				}

				randomDevice := NewRandomDevice()

				key := NewPeacemakrKey(cfg, randomDevice)

				ciphertext := Encrypt(cfg, key, plaintextIn, randomDevice)

				serialized := Serialize(ciphertext)
				if serialized == nil {
					t.Fatalf("serialize failed")
				}

				newCiphertext := Deserialize(serialized)

				plaintextOut, success := Decrypt(key, newCiphertext)
				if !success {
					t.Fatalf("Decrypt failed")
				}

				if !bytes.Equal(plaintextIn.data, plaintextOut.data) {
					t.Fatalf("plaintext data did not match")
				}

				if !bytes.Equal(plaintextIn.aad, plaintextOut.aad) {
					t.Fatalf("plaintext data did not match")
				}
			}
		}
	}
}
