package peacemakr_core_crypto

import (
	"bytes"
	"testing"
)

func TestEncrypt(t *testing.T) {
	cfg := CryptoConfig{
		mode:             ASYMMETRIC,
		asymmetricCipher: RSA_2048,
		symmetricCipher:  CHACHA20_POLY1305,
		digestAlgorithm:  SHA_384,
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

func TestSerialize(t *testing.T) {
	cfg := CryptoConfig{
		mode:             ASYMMETRIC,
		asymmetricCipher: RSA_2048,
		symmetricCipher:  CHACHA20_POLY1305,
		digestAlgorithm:  SHA_384,
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
