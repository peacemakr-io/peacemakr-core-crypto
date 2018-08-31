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
	crand "crypto/rand"
	crsa "crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	mrand "math/rand"
	"testing"
)

func SetUpPlaintext() Plaintext {
	pData := make([]byte, mrand.Uint32()%10000) // mod for test time
	pAAD := make([]byte, mrand.Uint32()%10000)
	mrand.Read(pData)
	mrand.Read(pAAD)
	return Plaintext{
		Data: pData,
		Aad:  pAAD,
	}
}

func GetNewRSAKey(bits int) ([]byte, []byte) {
	privKey, err := crsa.GenerateKey(crand.Reader, bits)
	if err != nil {
		panic(err)
	}

	privPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privKey),
		},
	)

	pubKey := privKey.PublicKey
	pub, err := x509.MarshalPKIXPublicKey(&pubKey)
	if err != nil {
		panic(err)
	}

	pubPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pub,
		},
	)

	return privPem, pubPem
}

func GetPubKey() []byte {
	return []byte(`-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArJ98LFNJ8OFRNGy6jTte
8YzaiO+iKt+MVOfEzOoM+yNrWB0qSnerJjiE0rZp0cu5KGLTLsG86XiHRW18efS2
9/qkDtJaMun0mhl2CTEDCpdfhd1PBOHBy5/fg47/ywajJNwH2axgsTYyne4kGxn6
eqX6QlddPt7R+Gb5NClpaRfqtXWxYgmi6dNkY/X6t0kyn6wKRuh6rCo64G5umyrI
PzcbzrCAPLUB1V40aiABL5n1AcnP5CGRr5XKA0Mhe3t+liERr5YORB2p839esGMQ
7XuSJnIJyrarkMtpC6YRZnjnRLxfZ3P8CLrmMMIVwYkw19ZCTJcdRBj1A2WXDnlg
zTYZ3ysGPz1ZXlhx4FsqV5na1EiEY4H2kzibpjoWVVqCkgvrI/LcDlsIpb9SOrRG
5HA1K4ZPt+/yphpVpKLuZyFx9LjuzlUWBzH0SZx5zp0kngN3RNO/8rC5BU2yOPmW
Ggsrg+uxkE6Ut/qyUShm3Ds0w+rUFlyUjHs/8ufKggnQaoORYp+46TGoOOjavb0A
CGuN3iSMaEdxRVKnd93AmQ8tMJd/UJ7U4yYRFOk+JT/2clKNiv8gtY0T9JzNt4OJ
7qeJWLsg67M2abnqpymcTYCE8LgDFxHcqEB89a1u9L+OrUWSWYQsATKB+Xh0HIwj
YyMNwzJygAFH8GLLzNQ8MxMCAwEAAQ==
-----END PUBLIC KEY-----`)
}

func GetPrivKey() []byte {
	return []byte(`-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`)
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

func TestAsymmetricEncryptFromPem(t *testing.T) {
	for j := AES_128_GCM; j <= CHACHA20_POLY1305; j++ {
		cfg := CryptoConfig{
			Mode:             ASYMMETRIC,
			AsymmetricCipher: RSA_4096,
			SymmetricCipher:  j,
			DigestAlgorithm:  SHA_512,
		}

		plaintextIn := SetUpPlaintext()

		randomDevice := NewRandomDevice()

		pubkey := NewPeacemakrKeyFromPubPem(cfg, GetPubKey())

		ciphertext, err := Encrypt(cfg, pubkey, plaintextIn, randomDevice)
		if err != nil {
			t.Fatalf("%v", err)
		}

		privkey := NewPeacemakrKeyFromPrivPem(cfg, GetPrivKey())

		plaintextOut, success := Decrypt(privkey, ciphertext)
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

func TestAsymmetricEncryptFromRandomPem(t *testing.T) {
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

			var priv []byte
			var pub []byte
			if i == RSA_2048 {
				priv, pub = GetNewRSAKey(2048)
			} else if i == RSA_4096 {
				priv, pub = GetNewRSAKey(4096)
			}

			//fmt.Println(string(priv))
			//fmt.Println(string(pub))

			privkey := NewPeacemakrKeyFromPrivPem(cfg, priv)
			pubkey := NewPeacemakrKeyFromPubPem(cfg, pub)

			ciphertext, err := Encrypt(cfg, pubkey, plaintextIn, randomDevice)
			if err != nil {
				t.Fatalf("%v", err)
			}

			plaintextOut, success := Decrypt(privkey, ciphertext)
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
