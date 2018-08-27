//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

package crypto

import (
	"bytes"
	"math/rand"
	"testing"
)

func SetUpPlaintext() Plaintext {
	pData := make([]byte, rand.Uint32()%10000) // mod for test time
	pAAD := make([]byte, rand.Uint32()%10000)
	rand.Read(pData)
	rand.Read(pAAD)
	return Plaintext{
		Data: pData,
		Aad:  pAAD,
	}
}

func TestAsymmetricEncrypt(t *testing.T) {
	for i := RSA_2048; i <= RSA_4096; i++ {
		for j := AES_128_GCM; j <= CHACHA20_POLY1305; j++ {
			cfg := CryptoConfig{
				Mode:             ASYMMETRIC,
				AsymmetricCipher: i,
				SymmetricCipher:  j,
				DigestAlgorithm:  SHA_512,
			}

			plaintextIn := SetUpPlaintext()

			randomDevice := NewRandomDevice()

			key := NewPeacemakrKey(cfg, randomDevice)

			ciphertext, err := Encrypt(cfg, key, plaintextIn, randomDevice)
			if err != nil {
				t.Fatalf("%v", err)
			}

			plaintextOut, success := Decrypt(key, ciphertext)
			if !success {
				t.Fatalf("Decrypt failed")
			}

			if !bytes.Equal(plaintextIn.Data, plaintextOut.Data) {
				t.Fatalf("plaintext data did not match")
			}

			if !bytes.Equal(plaintextIn.Aad, plaintextOut.Aad) {
				t.Fatalf("plaintext data did not match")
			}
		}
	}
}

func TestSymmetricEncrypt(t *testing.T) {
	for j := AES_128_GCM; j <= CHACHA20_POLY1305; j++ {
		cfg := CryptoConfig{
			Mode:             SYMMETRIC,
			AsymmetricCipher: NONE,
			SymmetricCipher:  j,
			DigestAlgorithm:  SHA_512,
		}

		plaintextIn := SetUpPlaintext()

		randomDevice := NewRandomDevice()

		key := NewPeacemakrKey(cfg, randomDevice)

		ciphertext, err := Encrypt(cfg, key, plaintextIn, randomDevice)
		if err != nil {
			t.Fatalf("%v", err)
		}

		plaintextOut, success := Decrypt(key, ciphertext)
		if !success {
			t.Fatalf("Decrypt failed")
		}

		if !bytes.Equal(plaintextIn.Data, plaintextOut.Data) {
			t.Fatalf("plaintext data did not match")
		}

		if !bytes.Equal(plaintextIn.Aad, plaintextOut.Aad) {
			t.Fatalf("plaintext data did not match")
		}
	}
}

func TestSerialize(t *testing.T) {
	for i := RSA_2048; i <= RSA_4096; i++ {
		for j := AES_128_GCM; j <= CHACHA20_POLY1305; j++ {
			for k := SHA_224; k <= SHA_512; k++ {
				cfg := CryptoConfig{
					Mode:             ASYMMETRIC,
					AsymmetricCipher: i,
					SymmetricCipher:  j,
					DigestAlgorithm:  k,
				}

				plaintextIn := SetUpPlaintext()

				randomDevice := NewRandomDevice()

				key := NewPeacemakrKey(cfg, randomDevice)

				ciphertext, err := Encrypt(cfg, key, plaintextIn, randomDevice)
				if err != nil {
					t.Fatalf("%v", err)
				}

				if err != nil {
					t.Fatalf("%v", err)
				}

				plaintextOut, success := Decrypt(key, ciphertext)
				if !success {
					t.Fatalf("Decrypt failed")
				}

				if !bytes.Equal(plaintextIn.Data, plaintextOut.Data) {
					t.Fatalf("plaintext data did not match")
				}

				if !bytes.Equal(plaintextIn.Aad, plaintextOut.Aad) {
					t.Fatalf("plaintext data did not match")
				}
			}
		}
	}
}
