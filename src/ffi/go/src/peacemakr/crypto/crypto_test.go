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
	"reflect"
	"testing"
)

func SetUpPlaintext() Plaintext {
	shouldUseData := bool(mrand.Uint32()%2 == 1)
	var pData []byte = nil
	if shouldUseData {
		pData = make([]byte, mrand.Uint32()%10000) // mod for test time
		mrand.Read(pData)
	}

	shouldUseAAD := bool(mrand.Uint32()%2 == 1)
	var pAAD []byte = nil
	if shouldUseAAD {
		pAAD = make([]byte, mrand.Uint32()%10000)
		mrand.Read(pAAD)
	}

	return Plaintext{
		Data: pData,
		Aad:  pAAD,
	}
}

func GetNewRSAKey(bits int) (string, string) {
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

	return string(privPem), string(pubPem)
}

func GetPubKey() string {
	return string(`-----BEGIN PUBLIC KEY-----
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

func GetPrivKey() string {
	return string(`-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`)
}

func TestAsymmetricEncrypt(t *testing.T) {
	if !PeacemakrInit() {
		t.Fatalf("Unable to successfully start and seed the CSPRNG")
	}
	for i := RSA_2048; i <= RSA_4096; i++ {
		for j := AES_128_GCM; j <= CHACHA20_POLY1305; j++ {
			go func(i, j int) {
				cfg := CryptoConfig{
					Mode:             ASYMMETRIC,
					AsymmetricCipher: AsymmetricCipher(i),
					SymmetricCipher:  SymmetricCipher(j),
					DigestAlgorithm:  SHA_512,
				}

				plaintextIn := SetUpPlaintext()

				randomDevice := NewRandomDevice()

				key := NewPeacemakrKeyAsymmetric(AsymmetricCipher(i), randomDevice)
				defer key.Destroy()

				key.SetSymmetricCipher(SymmetricCipher(j))

				ciphertext, err := Encrypt(key, plaintextIn, randomDevice)
				if err != nil && len(plaintextIn.Data) == 0 {
					return
				}

				if err != nil {
					t.Fatalf("%v", err)
				}

				serialized, err := Serialize(SHA_512, ciphertext)
				if err != nil {
					t.Fatalf("%v", err)
				}

				if plaintextIn.Aad != nil {
					AAD, err := ExtractUnverifiedAAD(serialized)
					if err != nil {
						t.Fatalf("Extract failed")
					}
					if !bytes.Equal(plaintextIn.Aad, AAD) {
						t.Fatalf("extracted aad did not match")
					}
				}

				deserialized, deserializedConfig, err := Deserialize(serialized)
				if err != nil {
					t.Fatalf("%v", err)
				}

				if !reflect.DeepEqual(*deserializedConfig, cfg) {
					t.Fatalf("did not deserialize the correct configuration")
				}

				plaintextOut, _, err := Decrypt(key, deserialized)
				if err != nil {
					t.Fatalf("Decrypt failed")
				}

				if !bytes.Equal(plaintextIn.Data, plaintextOut.Data) {
					t.Fatalf("plaintext data did not match")
				}

				if !bytes.Equal(plaintextIn.Aad, plaintextOut.Aad) {
					t.Fatalf("plaintext data did not match")
				}
			}(int(i), int(j))
		}
	}
}

func TestAsymmetricEncryptFromPem(t *testing.T) {
	if !PeacemakrInit() {
		t.Fatalf("Unable to successfully start and seed the CSPRNG")
	}

	cfg := CryptoConfig{
		Mode:             ASYMMETRIC,
		AsymmetricCipher: RSA_4096,
		SymmetricCipher:  AES_256_GCM, // The public key config infra assumes AES_256_GCM
		DigestAlgorithm:  SHA_512,
	}

	plaintextIn := SetUpPlaintext()

	randomDevice := NewRandomDevice()

	pubkey, err := NewPublicKeyFromPEM(GetPubKey())
	if err != nil {
		t.Fatal(err)
	}
	defer pubkey.Destroy()

	pubkey.SetSymmetricCipher(AES_256_GCM)

	ciphertext, err := Encrypt(pubkey, plaintextIn, randomDevice)
	if err != nil && len(plaintextIn.Data) == 0 {
		return
	}

	if err != nil {
		t.Fatalf("%v", err)
	}

	serialized, err := Serialize(SHA_512, ciphertext)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if plaintextIn.Aad != nil {
		AAD, err := ExtractUnverifiedAAD(serialized)
		if err != nil {
			t.Fatalf("Extract failed")
		}
		if !bytes.Equal(plaintextIn.Aad, AAD) {
			t.Fatalf("extracted aad did not match")
		}
	}

	deserialized, deserializedConfig, err := Deserialize(serialized)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !reflect.DeepEqual(*deserializedConfig, cfg) {
		t.Fatalf("did not deserialize the correct configuration")
	}

	privkey, err := NewPrivateKeyFromPEM(GetPrivKey())
	if err != nil {
		t.Fatal(err)
	}
	defer privkey.Destroy()

	plaintextOut, _, err := Decrypt(privkey, deserialized)
	if err != nil {
		t.Fatalf("Decrypt failed")
	}

	if !bytes.Equal(plaintextIn.Data, plaintextOut.Data) {
		t.Fatalf("plaintext data did not match")
	}

	if !bytes.Equal(plaintextIn.Aad, plaintextOut.Aad) {
		t.Fatalf("plaintext data did not match")
	}
}

func TestAsymmetricEncryptFromRandomPem(t *testing.T) {
	if !PeacemakrInit() {
		t.Fatalf("Unable to successfully start and seed the CSPRNG")
	}
	for i := RSA_2048; i <= RSA_4096; i++ {
		go func (i int) {
			cfg := CryptoConfig{
				Mode:             ASYMMETRIC,
				AsymmetricCipher: AsymmetricCipher(i),
				SymmetricCipher:  AES_256_GCM,
				DigestAlgorithm:  SHA_512,
			}

			plaintextIn := SetUpPlaintext()

			randomDevice := NewRandomDevice()

			var priv string
			var pub string
			if AsymmetricCipher(i) == RSA_2048 {
				priv, pub = GetNewRSAKey(2048)
			} else if AsymmetricCipher(i) == RSA_4096 {
				priv, pub = GetNewRSAKey(4096)
			}

			privkey, err := NewPrivateKeyFromPEM(priv)
			if err != nil {
				t.Fatal(err)
			}
			defer privkey.Destroy()

			pubkey, err := NewPublicKeyFromPEM(pub)
			if err != nil {
				t.Fatal(err)
			}
			defer pubkey.Destroy()

			pubkey.SetSymmetricCipher(AES_256_GCM)

			ciphertext, err := Encrypt(pubkey, plaintextIn, randomDevice)
			if err != nil && len(plaintextIn.Data) == 0 {
				return
			}
			if err != nil {
				t.Fatalf("%v", err)
			}

			serialized, err := Serialize(SHA_512, ciphertext)
			if err != nil {
				t.Fatalf("%v", err)
			}

			if plaintextIn.Aad != nil {
				AAD, err := ExtractUnverifiedAAD(serialized)
				if err != nil {
					t.Fatalf("Extract failed")
				}
				if !bytes.Equal(plaintextIn.Aad, AAD) {
					t.Fatalf("extracted aad did not match")
				}
			}

			deserialized, deserializedConfig, err := Deserialize(serialized)
			if err != nil {
				t.Fatalf("%v", err)
			}

			if !reflect.DeepEqual(*deserializedConfig, cfg) {
				t.Fatalf("did not deserialize the correct configuration")
			}

			plaintextOut, _, err := Decrypt(privkey, deserialized)
			if err != nil {
				t.Fatalf("Decrypt failed")
			}

			if !bytes.Equal(plaintextIn.Data, plaintextOut.Data) {
				t.Fatalf("plaintext data did not match")
			}

			if !bytes.Equal(plaintextIn.Aad, plaintextOut.Aad) {
				t.Fatalf("plaintext data did not match")
			}
		}(int(i))
	}
}

func TestSymmetricEncrypt(t *testing.T) {
	if !PeacemakrInit() {
		t.Fatalf("Unable to successfully start and seed the CSPRNG")
	}
	for j := AES_128_GCM; j <= CHACHA20_POLY1305; j++ {
		cfg := CryptoConfig{
			Mode:             SYMMETRIC,
			AsymmetricCipher: ASYMMETRIC_UNSPECIFIED,
			SymmetricCipher:  j,
			DigestAlgorithm:  SHA_512,
		}

		plaintextIn := SetUpPlaintext()

		randomDevice := NewRandomDevice()

		var key *PeacemakrKey
		var err error
		if j == AES_256_GCM || j == CHACHA20_POLY1305 {
			masterKey := NewPeacemakrKeySymmetric(SymmetricCipher(j), randomDevice)
			key, err = masterKey.HKDFKeygen(SymmetricCipher(j), SHA_512, []byte("abcdefghijklmnopqrstuvwxyz"))
			if err != nil {
				t.Fatalf("%v", err)
			}

			masterKey.Destroy()
		} else {
			origKey := NewPeacemakrKeySymmetric(SymmetricCipher(j), randomDevice)
			b, err := origKey.Bytes()
			if err != nil {
				origKey.Destroy()
				t.Fatalf("%v", err)
			}

			key = NewPeacemakrKeyFromBytes(SymmetricCipher(j), b)
		}


		ciphertext, err := Encrypt(key, plaintextIn, randomDevice)
		if err != nil && len(plaintextIn.Data) == 0 {
			return
		}
		if err != nil {
			key.Destroy()
			t.Fatalf("%v", err)
		}

		serialized, err := Serialize(SHA_512, ciphertext)
		if err != nil {
			key.Destroy()
			t.Fatalf("%v", err)
		}

		if plaintextIn.Aad != nil {
			AAD, err := ExtractUnverifiedAAD(serialized)
			if err != nil {
				key.Destroy()
				t.Fatalf("Extract failed")
			}
			if !bytes.Equal(plaintextIn.Aad, AAD) {
				key.Destroy()
				t.Fatalf("extracted aad did not match")
			}
		}

		deserialized, deserializedConfig, err := Deserialize(serialized)
		if err != nil {
			key.Destroy()
			t.Fatalf("%v", err)
		}

		if !reflect.DeepEqual(*deserializedConfig, cfg) {
			key.Destroy()
			t.Fatalf("did not deserialize the correct configuration, %v vs %v", *deserializedConfig, cfg)
		}

		plaintextOut, _, err := Decrypt(key, deserialized)
		if err != nil {
			key.Destroy()
			t.Fatalf("Decrypt failed")
		}

		if !bytes.Equal(plaintextIn.Data, plaintextOut.Data) {
			key.Destroy()
			t.Fatalf("plaintext data did not match")
		}

		if !bytes.Equal(plaintextIn.Aad, plaintextOut.Aad) {
			key.Destroy()
			t.Fatalf("plaintext data did not match")
		}
		key.Destroy()
	}
}

func parseKeyBits(cipher SymmetricCipher) int {
	switch cipher {
	case AES_128_GCM:
		return 128
	case AES_192_GCM:
		return 192
	case AES_256_GCM:
		return 256
	case CHACHA20_POLY1305:
		return 256
	default:
		return 0
	}
}

func TestSymmetricEncryptPassword(t *testing.T) {
	if !PeacemakrInit() {
		t.Fatalf("Unable to successfully start and seed the CSPRNG")
	}
	for j := AES_128_GCM; j <= CHACHA20_POLY1305; j++ {

		numIters := 10000
		key, salt, err := NewSymmetricKeyFromPassword(parseKeyBits(j), "abcdefghijklmnopqrstuvwxyz", numIters)
		if err != nil {
			t.Fatal(err)
		}

		key2, err := SymmetricKeyFromPasswordAndSalt(parseKeyBits(j), "abcdefghijklmnopqrstuvwxyz", salt, numIters)
		if err != nil {
			t.Fatal(err)
		}

		key3, _, err := NewSymmetricKeyFromPassword(parseKeyBits(j), "abcdefghijklmnopqrstuvwxyy", numIters)
		if err != nil {
			t.Fatal(err)
		}

		keyBytes, err := key.Bytes()
		if err != nil {
			key.Destroy()
			key2.Destroy()
			key3.Destroy()
			t.Fatalf("%v", err)
		}

		key2Bytes, err := key2.Bytes()
		if err != nil {
			key.Destroy()
			key2.Destroy()
			key3.Destroy()
			t.Fatalf("%v", err)
		}

		key3Bytes, err := key3.Bytes()
		if err != nil {
			key.Destroy()
			key2.Destroy()
			key3.Destroy()
			t.Fatalf("%v", err)
		}

		if bytes.Compare(keyBytes, key2Bytes) != 0 {
			key.Destroy()
			key2.Destroy()
			key3.Destroy()
			t.Fatalf("Keys 1 and 2 didn't compare equal")
		}

		if bytes.Compare(keyBytes, key3Bytes) == 0 {
			key.Destroy()
			key2.Destroy()
			key3.Destroy()
			t.Fatalf("Keys 1 and 3 did compare equal")
		}

		key.Destroy()
		key2.Destroy()
		key3.Destroy()
	}
}

func TestSerialize(t *testing.T) {
	if !PeacemakrInit() {
		t.Fatalf("Unable to successfully start and seed the CSPRNG")
	}
	for i := RSA_2048; i <= RSA_4096; i++ {
		for j := AES_128_GCM; j <= CHACHA20_POLY1305; j++ {
			for k := SHA_224; k <= SHA_512; k++ {
				go func(i, j, k int) {
					cfg := CryptoConfig{
						Mode:             ASYMMETRIC,
						AsymmetricCipher: AsymmetricCipher(i),
						SymmetricCipher:  SymmetricCipher(j),
						DigestAlgorithm:  MessageDigestAlgorithm(k),
					}

					plaintextIn := SetUpPlaintext()

					randomDevice := NewRandomDevice()

					key := NewPeacemakrKeyAsymmetric(AsymmetricCipher(i), randomDevice)
					defer key.Destroy()

					key.SetSymmetricCipher(SymmetricCipher(j))

					ciphertext, err := Encrypt(key, plaintextIn, randomDevice)
					if err != nil && len(plaintextIn.Data) == 0 {
						return
					}
					if err != nil {
						t.Fatalf("%v", err)
					}

					serialized, err := Serialize(MessageDigestAlgorithm(k), ciphertext)
					if err != nil {
						t.Fatalf("%v", err)
					}

					if plaintextIn.Aad != nil {
						AAD, err := ExtractUnverifiedAAD(serialized)
						if err != nil {
							t.Fatalf("Extract failed")
						}
						if !bytes.Equal(plaintextIn.Aad, AAD) {
							t.Fatalf("extracted aad did not match")
						}
					}

					deserialized, deserializedConfig, err := Deserialize(serialized)
					if err != nil {
						t.Fatalf("%v", err)
					}

					if !reflect.DeepEqual(*deserializedConfig, cfg) {
						t.Fatalf("did not deserialize the correct configuration")
					}

					plaintextOut, _, err := Decrypt(key, deserialized)
					if err != nil {
						t.Fatalf("Decrypt failed")
					}

					if !bytes.Equal(plaintextIn.Data, plaintextOut.Data) {
						t.Fatalf("plaintext data did not match")
					}

					if !bytes.Equal(plaintextIn.Aad, plaintextOut.Aad) {
						t.Fatalf("plaintext data did not match")
					}
				}(int(i), int(j), int(k))
			}
		}
	}
}

func TestECDHSerialize(t *testing.T) {
	if !PeacemakrInit() {
		t.Fatalf("Unable to successfully start and seed the CSPRNG")
	}
	for j := AES_128_GCM; j <= CHACHA20_POLY1305; j++ {
		for k := SHA_224; k <= SHA_512; k++ {
			for curve := ECDH_P256; curve <= ECDH_P521; curve++ {
				go func(j, k, curve int) {

					plaintextIn := SetUpPlaintext()

					randomDevice := NewRandomDevice()

					myKey := NewPeacemakrKeyAsymmetric(AsymmetricCipher(curve), randomDevice)
					defer myKey.Destroy()

					peerKey := NewPeacemakrKeyAsymmetric(AsymmetricCipher(curve), randomDevice)
					defer peerKey.Destroy()

					secKey := myKey.ECDHKeygen(SymmetricCipher(j), peerKey)
					defer secKey.Destroy()

					secKeyCfg, err := secKey.Config()
					if err != nil {
						t.Fatalf("%v", err)
					}

					ciphertext, err := Encrypt(secKey, plaintextIn, randomDevice)
					if err != nil && len(plaintextIn.Data) == 0 {
						return
					}

					if err != nil {
						t.Fatalf("%v", err)
					}

					serialized, err := Serialize(MessageDigestAlgorithm(k), ciphertext)
					if err != nil {
						t.Fatalf("%v", err)
					}

					if plaintextIn.Aad != nil {
						AAD, err := ExtractUnverifiedAAD(serialized)
						if err != nil {
							t.Fatalf("Extract failed")
						}
						if !bytes.Equal(plaintextIn.Aad, AAD) {
							t.Fatalf("extracted aad did not match")
						}
					}

					deserialized, deserializedConfig, err := Deserialize(serialized)
					if err != nil {
						t.Fatalf("%v", err)
					}

					if !reflect.DeepEqual(*deserializedConfig, secKeyCfg) {
						t.Fatalf("did not deserialize the correct configuration, %v, %v", *deserializedConfig, secKeyCfg)
					}

					plaintextOut, _, err := Decrypt(secKey, deserialized)
					if err != nil {
						t.Fatalf("Decrypt failed")
					}

					if !bytes.Equal(plaintextIn.Data, plaintextOut.Data) {
						t.Fatalf("plaintext data did not match")
					}

					if !bytes.Equal(plaintextIn.Aad, plaintextOut.Aad) {
						t.Fatalf("plaintext data did not match")
					}
				}(int(j), int(k), int(curve))
			}
		}
	}
}

func TestSignatures(t *testing.T) {
	if !PeacemakrInit() {
		t.Fatalf("Unable to successfully start and seed the CSPRNG")
	}
	for i := RSA_2048; i <= RSA_4096; i++ {
		for j := AES_128_GCM; j <= CHACHA20_POLY1305; j++ {
			for k := SHA_224; k <= SHA_512; k++ {
				go func(i, j, k int) {
					cfg := CryptoConfig{
						Mode:             ASYMMETRIC,
						AsymmetricCipher: AsymmetricCipher(i),
						SymmetricCipher:  SymmetricCipher(j),
						DigestAlgorithm:  MessageDigestAlgorithm(k),
					}

					plaintextIn := SetUpPlaintext()

					randomDevice := NewRandomDevice()

					key := NewPeacemakrKeyAsymmetric(AsymmetricCipher(i), randomDevice)
					defer key.Destroy()

					key.SetSymmetricCipher(SymmetricCipher(j))

					ciphertext, err := Encrypt(key, plaintextIn, randomDevice)
					if err != nil && len(plaintextIn.Data) == 0 {
						return
					}
					if err != nil {
						t.Fatalf("%v", err)
					}
					err = Sign(key, plaintextIn, MessageDigestAlgorithm(k), ciphertext)

					serialized, err := Serialize(MessageDigestAlgorithm(k), ciphertext)
					if err != nil {
						t.Fatalf("%v", err)
					}

					if plaintextIn.Aad != nil {
						AAD, err := ExtractUnverifiedAAD(serialized)
						if err != nil {
							t.Fatalf("Extract failed")
						}
						if !bytes.Equal(plaintextIn.Aad, AAD) {
							t.Fatalf("extracted aad did not match")
						}
					}

					deserialized, deserializedConfig, err := Deserialize(serialized)
					if err != nil {
						t.Fatalf("%v", err)
					}

					if !reflect.DeepEqual(*deserializedConfig, cfg) {
						t.Fatalf("did not deserialize the correct configuration")
					}

					plaintextOut, needVerify, err := Decrypt(key, deserialized)
					if err != nil {
						t.Fatalf("Decrypt failed")
					}
					if !needVerify {
						t.Fatalf("Decrypt failed - should need verify")
					}

					err = Verify(key, plaintextOut, deserialized)
					if err != nil {
						t.Fatalf("Verify failed")
					}

					if !bytes.Equal(plaintextIn.Data, plaintextOut.Data) {
						t.Fatalf("plaintext data did not match")
					}

					if !bytes.Equal(plaintextIn.Aad, plaintextOut.Aad) {
						t.Fatalf("plaintext data did not match")
					}
				}(int(i), int(j), int(k))
			}
		}
	}
}

func TestIssueNumber27FailToDecrypt(t *testing.T) {
	if !PeacemakrInit() {
		t.Fatalf("Unable to successfully start and seed the CSPRNG")
	}

	EncryptedBytes := "AAAEHgAABA0AAAAAAwAAAAEBAgIAAAIAAAAAAIWesorxYFmTFTivS6OXTemz+/dAeD6dd+TYBOIWqKVZGgbQ1VgnvcU+nDcPVJqIDBYPE5u4Vx283F+21wCeFWGeeMMST9be9bxRXqnRHcyu5q2zWJ86EJAS7fcJtqTqUNRHyCLpQaekYpp/VxKjk4qNXbdcttGqi69Vr9DH1Jjsks2ENETYkxWIRg4zfFTNqtm16OKY/zI0Gts3OBDlbQstRA/XhazbrxaU8EOfE4aW3AkjzubYGniAXUyn9/2UYsB0GA7ABptqA4Kb3lI4bzLDEgt77EOaLF+x/KcppS90zm+Oq8MX8E2JwzQH0UrRyY+mmvkGHFnLqZrApzpnbRhH3o8KgN1ynZJU7Azibd7zTCrBYxWdihUn10l+yGima9cbLcCTJXwOhytiW/ntOZo/L2noELHuXQ+00CDFAOTSvDq1d8dQqU9nPoFemplhz7j4zuHwJ1MRRVe999u/3/uzewZvdacOVXxR7nQTjT+RUeqh9xhNcpEn8WwPVEjvvgvWtxQ43oA1T76vd0W34w/FJUFfrcrLP36E3e1sl/0OuIzhX9aIy2+2198eT89oKFOsGgGYsS4Z8R/PnLwwcw4bGKBnoLV6qNy59e3PEtwCxmdtwEjRl+zUMQtguxB2vg9ujRHZVBDE5TwE6s321JlCbWZ+gD68MK2Hkc7WKnNKAAAADAAAAADT4hIm+8GJtFOaIegAAAAQAAAAACC444WSNi247Vylls+h/5kAAAAAAAAAAAAAAawAAAAALZso9KFyh29Ja3s6KVH/vdp+6P6GWH/zrnME3+8VwJC02vZ5FgLMJMjGmmdF1r3c7Bc5j4bUhKyKODLh+4tnYra6jR2ap15z1Afn5fP7uT2uqSXuPdFB7eRByFBrlNW9cuIfXhrQWjSp91Sz079oTEFarOfqTI/ORZyG/h3zUvCRKGSfgF+xDL00V0snROhg2HdK3CUZBvdCAJVDaFDYXaq1FtLFkJzNCeBd+PAtbMM9lcqTsYxHZEDHlEJDQA12Z52DzrFWonN7QgDey4bzgbN2WY9IClbEszpVZXhyrprZj4TsGyFCuwQT/dwLmlFWnYGFj3/sKcSNlHrG1YdtWJt0tvZaQf4fjc2TLwWiLSseMG6c97PVTn9blL1dgjm0VyvudEOFwJNMHGi0JvSY8leFD0tQ5qXo+w73AUmLWQ/F++qQc4hgT7XXuhJmXeuSh3fnvfhHqojPWHZ40e04Yr8HmoyOOaiBGVpjU7rbTIH4korcGcW3BMOMBzZTUIzexjeLTte63lUe/xvpgAuCVtLXBQgs81TlngXLmz8NvbAnlJj3mbGJE/Nkk2sAAAABAAAAAAAAAABAAAAAAIQBX8pvxbKj84Um0UMGQWNUjggUVRiU7liVNPMZPdVoLS12YBhNBy8hvcUKdnWRI3FwcbPqiUh1TDC+Dr85vYo="
	_ = "-----BEGIN RSA PRIVATE KEY-----\n" +
		"MIIJKgIBAAKCAgEA5bFquCdimb6H3WQNXj45LvBp9YBML4IQ8qJyk52PFDu5GNVz\n" +
		"WvctnY7yfXic5RGG/0168jWbzb6hRyLJUp3s91DoC/HgvYAUhYVAuL5r6P/49abH\n" +
		"lR6WTxSLKX1Ik5CLf1rObxQ6pKapJ+/DuJ5CwEsYhBZflnP2CFycXgqb/kizwQem\n" +
		"BnWJs3gs48UznFoFldiI06hhK4z6XIR45nUL6m5n9sbY1MeMT1fUwtlYLZpEPmID\n" +
		"kU2nxSHDw0PX9mn5ps62Ju+SudpKaUdG44TT9LzjKqZezfzgyABeaF9jTg225lgB\n" +
		"UxoyFcPqSHdBNtBHico2HiuLa5+oT2u4b8A3pUP3dqTHeTciJTUm7yxSG4mS861J\n" +
		"nsIHsDKpTYDlWw7bxw5k1u3XTbgGpcvzhY/GhmYlts0DD/Sg/0mbXjXCdJB9A8nw\n" +
		"uPH2Ytok2nPtjpSUOmxDV4ViyxT37J1aQa/ADItXVAYRHlBkt039CZ2VZFU/cJ5Z\n" +
		"PMLZkgYpXUQVD3ACy+PgLYukbONNK5Xb037YuZfZjpP895ggf959N/sZmFX9cD1B\n" +
		"BdMB9tJiAOeCXeNQVDHOod/pu/yXqCsX2qhfFRhcvvCPCBSSWth6awDgIvnhUg5Q\n" +
		"0No3Q61Mo4B2DIrNOjGkgDszgRoqIrdACQbfhKJvkNANZm8SjgVW582oCBsCAwEA\n" +
		"AQKCAgEAn9w21iwzJ6W/kYoM88aCrfSNClxcqcPwX65H6A0Eg6R9UpdcTbcyfDH8\n" +
		"+u5y48qrFgyqwOAmq689N/EyBNn9DrO0jHuvWrRFlBgFz45YNDXS48VLqrE7E5bM\n" +
		"s/eKB4nWTLC6c/y0Q9vqZu0sXtVmx8Z8LZIUvPXAClnKSnk/0F5xHKtiFaTATbQa\n" +
		"KfwZy3ur33pw4D6UQmc/6BwauOpFfMeSe+IxDwZC1QXgAiyafkKbtH8q1HojhcPW\n" +
		"J5SUPd/L7Rh5FegvSkJu/46n+7l6ex7rS8e2u85/8zKugh3BU5Wf8fjWEyxsJ1HP\n" +
		"QNge/zM+VtvxhlXwFttrnLrwBnbVQlJtEKUE2XHdNNgtP4GL32SiZjSQfEQcMrWw\n" +
		"cSSTOCVb21hZ42Vq8YykmMhPDkIy2f+yi9X0IUIMbTZQv2KjYzF+0THnVaDFFKi1\n" +
		"oFq6ESiET7o38WODi7u5L6ZnFs7xVEX2M5S+knLhsi/t2tNvcXjzCrsVTsKp1DaI\n" +
		"JzRB7DZv4yfT4+UEl14byevik0Jun3ngqZ62+hZFMNTapGHkxnzQnTGu/ayJQfym\n" +
		"7S31OaVFSTnOUXq0I70NLg9w87Ptqt42CvbSi8r6TlSqw64wUevFjOjUrK//RbIY\n" +
		"OAeEHpWeiDoSbSeqdtCudkecI8vBunOIETaXbeLPj5xM0o1UkqECggEBAOZs3F89\n" +
		"iccUAwqziWoybVeFw2yOlya5EKANu8mllbKXWrc7Vwbmr/Nuz2BtyI1k5xMJm/f2\n" +
		"ilgtJmd6p3naE1v91U7sGLFmneGjTng2pVKPt5BGOv9q7jtFTHLFVVQ0caUQE5Yg\n" +
		"Zws1ev6VdWDlLntLES9PSc41Ibj2tIurJujqzuyfgU2SGxZCkSyZMzY4It8OtVq5\n" +
		"oPKZD8I8yIZ/1WgX4KeUu5OJ4PNdc+lHyPoR4Yf6XY1c4M4dkIpGHqI8I7FsJctB\n" +
		"xLPQrU5ANT941vWjqPkT+t/MKwBgM19tZ/Z0e3LIMW1lFYSNv4zWcb3Riw/I89mG\n" +
		"ZePEbRh/MsDp5N8CggEBAP8vwHKiCHRZzEkyIu5Dr3Mrabs0Nh7F6HU/X2Yt5YGD\n" +
		"H2zAl1JUJNpylasf9P4+iBMIpKECbHojnT13fzIR+D7KSPIAVzLUTU0KcT44j9i3\n" +
		"wKDPzx4yr8CA4SO90h/Tsnnra+3lfsy8+viLXyhQL4Spy39K6OAqF1oJkL3AIxNt\n" +
		"9q5t7x3aTdWlBATWa7jYbylm5yV1ZeIgVDz28uYJAA1mQbyfhPr6u0vUNIMCKp4h\n" +
		"pxb8GPze/OUmOSSV0dF150FaYIs3psGvVCYdmz9k6qY+pPvQqYAh1O96T8Hdy8pP\n" +
		"jXbCC57/7nlcf/UrXLxZtadhdlVrvq9f5UaS4Zn1qEUCggEBAMCxJnSKzK3rYUPQ\n" +
		"schaFTAMz0j30RTzzCBce758Nzxa7+SsvfEqdtd2wfrcs8ryJ363GXP5+uUUFLqS\n" +
		"Sn1OzcOu+HOAYoHv03W+kD9dS1FIl/QRlwLDVCfCotSTivDYznR/hjGUNTedaJZ/\n" +
		"O+JkpUM7mkpa3tiPe/zmakMmRGqg+ZvNI19QIFC0KB0InFfqB9dKwIP3Gc3mC9Sd\n" +
		"6f735emfliHt8hLGSZSagPUDL+FXlKeWyicOFXyoIphPXQzEiAC19MEN5cWNa3A1\n" +
		"p5HFptVSIFryx2fhn9A3op5ZqofiDt4E5biawKzRsO7A4esf0U/I94rfplMbjzPe\n" +
		"Iv5KWjcCggEAbro0okkGrB3O06/qkkJSXgHnZfCYzy+G12FBLuAZZuITf6ftwS57\n" +
		"s0HnCZLbRnqxprioXqjjkvfjIam5SmubsPsrPb7CF28hf51ZV+tJF3tcHSsurubF\n" +
		"dh02E8Eo7OB54Ac0FMzxATu7Fp+7EY4BoGngwAIsHCCHc20VHhDB54teb3+KMwTn\n" +
		"ox1wKf00TsezLF7XS1yucbkfdDifWwtqt2W4fnUlSZYEMToJ8xK8lVL64rFO0mKb\n" +
		"j37Par2LhnzHdIcXvzDNrds7AzLzi0Vpv+sMwatf8RY9BBCpjPCFnep48p/uVPau\n" +
		"boChkStYmO3AMbnLk/MlkYllvgK724dJlQKCAQEAjUkydLRrruJDMK2C+KI3uuM1\n" +
		"IfTaLsfDFiTN1/BEIswRXLZlc4hykWZuOaEU+d7CvkI5riCo9c0e6c383pTWrm39\n" +
		"Ej0SqtgGmFiGvq9dDY5FAyiqyyDROJLoK5s2rjq8Fzz9CGNGAz7apirIT2GDFRuI\n" +
		"jNqEJgS8ZogunC1tRhJu0qJC8lWNeyvGhvEhYuw6wEvvDfDgeWKrFGBl52Hj7ZKn\n" +
		"AwiNyl6wNqi27u7tqecoi4UUf85LwL9SSGXb7lFAmZ/0WkUGx9Z7ImH/rslTLGSQ\n" +
		"WA6GzmLXEW+3piXdUgU5lplOdWUVvysuaKufgtEBbNqWJd32jztbWa2DJsyevA==\n" +
		"-----END RSA PRIVATE KEY-----"

	_, _, err := Deserialize([]byte(EncryptedBytes))
	if err == nil {
		t.Fatalf("Did not fail to deserialize")
	}
}
