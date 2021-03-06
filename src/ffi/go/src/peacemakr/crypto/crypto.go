//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

package crypto

// #cgo LDFLAGS: -lpeacemakr-core-crypto -L${SRCDIR}/lib -Wl,-rpath ${SRCDIR}/lib
// #cgo CFLAGS: -I${SRCDIR}/include -I${SRCDIR}/openssl/include
// #include <peacemakr/crypto.h>
// #include <peacemakr/random.h>
// #include <stdlib.h>
// #include <string.h>
/*
   extern int go_rng(unsigned char *, size_t);
   extern char *go_rng_err(int);

   static inline random_device_t cbridge() {
		random_device_t rand = {
			.generator = &go_rng,
			.err = (const char *(*)(int))(&go_rng_err)
		};
		return rand;
   }

   extern void go_log_export(char *);
   static inline peacemakr_log_cb go_log_cbridge() {
   		return (peacemakr_log_cb)go_log_export;
   }
*/
import "C"
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"unsafe"
)

//export go_rng
func go_rng(buf *C.uchar, size C.size_t) C.int {
	randomBytes := make([]byte, size)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return 1
	}
	if buf == nil {
		return 2
	}
	if size == 0 {
		return 3
	}
	C.memcpy(unsafe.Pointer(buf), unsafe.Pointer(&randomBytes[0]), size)
	return 0
}

//export go_rng_err
func go_rng_err(err C.int) *C.char {
	switch err {
	case 0:
		return nil
	case 1:
		return C.CString("error ocurred while reading random numbers")
	case 2:
		return C.CString("buf passed in was nil")
	case 3:
		return C.CString("size passed in was zero")
	}
	return nil
}

//export go_log_export
func go_log_export(buf *C.char) {
	goStr := C.GoString(buf)
	log.Print(goStr)
}

func NewRandomDevice() RandomDevice {
	return RandomDevice{
		randomDevice: C.cbridge(),
	}
}

type RandomDevice struct {
	randomDevice C.random_device_t
}

type SymmetricCipher int

const (
	SYMMETRIC_UNSPECIFIED SymmetricCipher = 0
	AES_128_GCM       SymmetricCipher = 1
	AES_192_GCM       SymmetricCipher = 2
	AES_256_GCM       SymmetricCipher = 3
	CHACHA20_POLY1305 SymmetricCipher = 4
)

type AsymmetricCipher int

const (
	ASYMMETRIC_UNSPECIFIED     AsymmetricCipher = 0
	RSA_2048 AsymmetricCipher = 1
	RSA_4096 AsymmetricCipher = 2
	ECDH_P256 AsymmetricCipher = 3
	ECDH_P384 AsymmetricCipher = 4
	ECDH_P521 AsymmetricCipher = 5
	ECDH_SECP256K1 AsymmetricCipher = 6
)

type MessageDigestAlgorithm int

const (
	DIGEST_UNSPECIFIED MessageDigestAlgorithm = 0
	SHA_224  MessageDigestAlgorithm = 1
	SHA_256  MessageDigestAlgorithm = 2
	SHA_384  MessageDigestAlgorithm = 3
	SHA_512  MessageDigestAlgorithm = 4
)

type EncryptionMode int

const (
	SYMMETRIC  EncryptionMode = 0
	ASYMMETRIC EncryptionMode = 1
)

type CryptoConfig struct {
	Mode             EncryptionMode
	SymmetricCipher  SymmetricCipher
	AsymmetricCipher AsymmetricCipher
	DigestAlgorithm  MessageDigestAlgorithm
}

// ========================= File-internal helpers =========================
func configToInternal(config CryptoConfig) C.crypto_config_t {
	return C.crypto_config_t{
		mode:             C.encryption_mode(config.Mode),
		symm_cipher:      C.symmetric_cipher(config.SymmetricCipher),
		asymm_cipher:     C.asymmetric_cipher(config.AsymmetricCipher),
		digest_algorithm: C.message_digest_algorithm(config.DigestAlgorithm),
	}
}

func configFromInternal(config C.crypto_config_t) CryptoConfig {
	return CryptoConfig{
		Mode:             EncryptionMode(config.mode),
		SymmetricCipher:  SymmetricCipher(config.symm_cipher),
		AsymmetricCipher: AsymmetricCipher(config.asymm_cipher),
		DigestAlgorithm:  MessageDigestAlgorithm(config.digest_algorithm),
	}
}

type Plaintext struct {
	Data []byte
	Aad  []byte
}

func plaintextToInternal(plaintext Plaintext) C.plaintext_t {
	return C.plaintext_t{
		data_len: C.size_t(len(plaintext.Data)),
		data:     (*C.uchar)(C.CBytes(plaintext.Data)),
		aad_len:  C.size_t(len(plaintext.Aad)),
		aad:      (*C.uchar)(C.CBytes(plaintext.Aad)),
	}
}

func freeInternalPlaintext(internalPlaintext *C.plaintext_t) {
	if internalPlaintext == nil {
		return
	}

	C.free(unsafe.Pointer(internalPlaintext.data))
	C.free(unsafe.Pointer(internalPlaintext.aad))
}

// ========================= Package helpers =========================

func GetMaxSupportedVersion() uint8 {
	return uint8(C.get_max_version())
}

func PeacemakrInit() bool {
	C.peacemakr_set_log_callback(C.go_log_cbridge())

	return bool(C.peacemakr_init())
}

// ========================= Core types =========================

type CiphertextBlob struct {
	blob *C.ciphertext_blob_t
}

type PeacemakrKey struct {
	key *C.peacemakr_key_t
}

// ========================= Raw key creation =========================

func NewPeacemakrKeySymmetric(config SymmetricCipher, rand RandomDevice) *PeacemakrKey {
	return &PeacemakrKey{
		key: C.peacemakr_key_new_symmetric((C.symmetric_cipher)(config), (*C.random_device_t)(unsafe.Pointer(&rand.randomDevice))),
	}
}

func NewPeacemakrKeyAsymmetric(asymm AsymmetricCipher, symm SymmetricCipher, rand RandomDevice) *PeacemakrKey {
	return &PeacemakrKey{
		key: C.peacemakr_key_new_asymmetric((C.asymmetric_cipher)(asymm), (C.symmetric_cipher)(symm), (*C.random_device_t)(unsafe.Pointer(&rand.randomDevice))),
	}
}

func NewPeacemakrKeyFromBytes(cipher SymmetricCipher, contents []byte) *PeacemakrKey {
	cBytes := (*C.uint8_t)(C.CBytes(contents))
	defer C.free(unsafe.Pointer(cBytes))
	cNumBytes := (C.size_t)(len(contents))
	return &PeacemakrKey{
		key: C.peacemakr_key_new_bytes((C.symmetric_cipher)(cipher), cBytes, cNumBytes),
	}
}

func newPeacemakrKeyFromPassword(cipher SymmetricCipher, digest MessageDigestAlgorithm, passwordStr string, salt []byte, iterationCount int) *PeacemakrKey {
	password := []byte(passwordStr)
	cBytes := (*C.uint8_t)(C.CBytes(password))
	defer C.free(unsafe.Pointer(cBytes))
	cNumBytes := (C.size_t)(len(password))

	cSalt := (*C.uint8_t)(C.CBytes(salt))
	defer C.free(unsafe.Pointer(cSalt))
	cNumSalt := (C.size_t)(len(salt))

	return &PeacemakrKey {
	    key: C.peacemakr_key_new_from_password((C.symmetric_cipher)(cipher), (C.message_digest_algorithm)(digest), cBytes, cNumBytes, cSalt, cNumSalt, (C.size_t)(iterationCount)),
	}
}

func newPeacemakrKeyFromPubPem(symm SymmetricCipher, contents []byte, trustStorePath []byte) *PeacemakrKey {
	cBytes := (*C.char)(C.CBytes(contents))
	defer C.free(unsafe.Pointer(cBytes))

	tsBytes := (*C.char)(C.CBytes(trustStorePath))
  defer C.free(unsafe.Pointer(tsBytes))

	return &PeacemakrKey{
		key: C.peacemakr_key_new_pem_pub((C.symmetric_cipher)(symm), cBytes, C.size_t(len(contents)), tsBytes, C.size_t(len(trustStorePath))),
	}
}

func newPeacemakrKeyFromPrivPem(symm SymmetricCipher, contents []byte) *PeacemakrKey {
	cBytes := (*C.char)(C.CBytes(contents))
	defer C.free(unsafe.Pointer(cBytes))
	return &PeacemakrKey{
		key: C.peacemakr_key_new_pem_priv((C.symmetric_cipher)(symm), cBytes, C.size_t(len(contents))),
	}
}

// ========================= Internal helpers for wrappers =========================

func GetECKeyTypeFromPubPemStr(pubPEM string) (AsymmetricCipher, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return ASYMMETRIC_UNSPECIFIED, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return ASYMMETRIC_UNSPECIFIED, err
	}

	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		if pub.Curve == elliptic.P256() {
			return ECDH_P256, nil
		} else if pub.Curve == elliptic.P384() {
			return ECDH_P384, nil
		} else if pub.Curve == elliptic.P521() {
			return ECDH_P521, nil
		}
	default:
		break // fall through
	}
	return ASYMMETRIC_UNSPECIFIED, errors.New("key type is not EC")
}

func GetECKeyTypeFromPrivPemStr(pubPEM string) (AsymmetricCipher, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return ASYMMETRIC_UNSPECIFIED, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return ASYMMETRIC_UNSPECIFIED, err
	}

	if priv.Curve == elliptic.P256() {
		return ECDH_P256, nil
	} else if priv.Curve == elliptic.P384() {
		return ECDH_P384, nil
	} else if priv.Curve == elliptic.P521() {
		return ECDH_P521, nil
	}

	return ASYMMETRIC_UNSPECIFIED, errors.New("key type is not EC")
}

func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("Key type is not RSA")
}

func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func getBitLenFromRsaPubPemStr(pubRSA string) (int, error) {
	rsaKey, err := ParseRsaPublicKeyFromPemStr(pubRSA)
	if err != nil {
		return 0, err
	}
	return rsaKey.N.BitLen(), nil
}

func getBitLenFromRsaPrivPemStr(privRSA string) (int, error) {
	rsaKey, err := ParseRsaPrivateKeyFromPemStr(privRSA)
	if err != nil {
		return 0, err
	}
	return rsaKey.N.BitLen(), nil
}

func GetConfigFromPubKey(pubKey string) (AsymmetricCipher, error) {
	// First try to get it as an EC key
	asymKeyLen, err := GetECKeyTypeFromPubPemStr(pubKey)
	if err != nil { // It's not an EC key
		bitLength, err := getBitLenFromRsaPubPemStr(string(pubKey))
		if err != nil {
			return ASYMMETRIC_UNSPECIFIED, errors.New("failed to get bit length from public rsa key")
		}
		if bitLength == 4096 {
			asymKeyLen = RSA_4096
		} else if bitLength == 2048 {
			asymKeyLen = RSA_2048
		} else {
			return ASYMMETRIC_UNSPECIFIED, errors.New("unknown bitlength for RSA key")
		}
	}

	return asymKeyLen, nil
}

func GetConfigFromPrivKey(privKey string) (AsymmetricCipher, error) {
	// First try to get it as an EC key
	asymKeyLen, err := GetECKeyTypeFromPrivPemStr(privKey)
	if err != nil { // It's not an EC key
		bitLength, err := getBitLenFromRsaPrivPemStr(privKey)
		if err != nil {
			return ASYMMETRIC_UNSPECIFIED, errors.New("failed to get bit length from public rsa key")
		}
		if bitLength == 4096 {
			asymKeyLen = RSA_4096
		} else if bitLength == 2048 {
			asymKeyLen = RSA_2048
		} else {
			return ASYMMETRIC_UNSPECIFIED, errors.New("unknown bitlength for RSA key")
		}
	}

	return asymKeyLen, nil
}

// ========================= Wrapped key creation =========================

func SymmetricKeyFromBytes(keyBytes []byte) (*PeacemakrKey, error) {

	var cipher SymmetricCipher

	switch len(keyBytes) {
	case 128 / 8:
		cipher = AES_128_GCM
	case 192 / 8:
		cipher = AES_192_GCM
	case 256 / 8:
		cipher = AES_256_GCM
	default:
		return nil, errors.New("unknown length for keyBytes, need to use raw key creation APIs")
	}

	return NewPeacemakrKeyFromBytes(cipher, keyBytes), nil
}

func NewSymmetricKeyFromPassword(keylenBits int, passwordStr string, iterationCount int) (*PeacemakrKey, []byte, error) {

	var cipher SymmetricCipher
	switch keylenBits {
	case 128:
		cipher = AES_128_GCM
	case 192:
		cipher = AES_192_GCM
	case 256:
		cipher = AES_256_GCM
	default:
		return nil, nil, errors.New("unknown length for keylenBits, acceptable values are 128, 192, 256")
	}

	salt := make([]byte, 256 / 8)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, nil, errors.New("unable to read salt from random string")
	}

	outKey := newPeacemakrKeyFromPassword(cipher, SHA_256, passwordStr, salt, iterationCount)
	return outKey, salt, nil
}

func SymmetricKeyFromPasswordAndSalt(keylenBits int, passwordStr string, salt []byte, iterationCount int) (*PeacemakrKey, error) {

	var cipher SymmetricCipher
	switch keylenBits {
	case 128:
		cipher = AES_128_GCM
	case 192:
		cipher = AES_192_GCM
	case 256:
		cipher = AES_256_GCM
	default:
		return nil, errors.New("unknown length for keylenBits, acceptable values are 128, 192, 256")
	}

	outKey := newPeacemakrKeyFromPassword(cipher, SHA_256, passwordStr, salt, iterationCount)
	return outKey, nil
}


func NewPublicKeyFromPEM(symm SymmetricCipher, contents string, trustStorePath string) (*PeacemakrKey, error) {
	return newPeacemakrKeyFromPubPem(symm, []byte(contents), []byte(trustStorePath)), nil
}

func NewPrivateKeyFromPEM(symm SymmetricCipher, contents string) (*PeacemakrKey, error) {
	return newPeacemakrKeyFromPrivPem(symm, []byte(contents)), nil
}

// ========================= Operations to do on keys =========================

func (k *PeacemakrKey) IsValid() bool {
	return k.key != nil
}

func (k *PeacemakrKey) GetCSR(org, commonName []byte) ([]byte, error) {
  if !k.IsValid() {
    return nil, errors.New("invalid key")
  }

  orgBytes := (*C.uint8_t)(C.CBytes(org))
  defer C.free(unsafe.Pointer(orgBytes))

  cnBytes := (*C.uint8_t)(C.CBytes(commonName))
  defer C.free(unsafe.Pointer(cnBytes))

  var buf *byte
  defer C.free(unsafe.Pointer(buf))
  var bufSize C.size_t

  success := C.peacemakr_key_generate_csr(k.key, orgBytes, C.size_t(len(org)), cnBytes, C.size_t(len(commonName)), (**C.uint8_t)(unsafe.Pointer(&buf)), (*C.size_t)(&bufSize))
  if !success {
    return nil, errors.New("failed to get bytes from peacemakr key")
  }

  return C.GoBytes(unsafe.Pointer(buf), C.int(bufSize)), nil
}

func (k *PeacemakrKey) AddCertificate(cert []byte) error {
  if !k.IsValid() {
    return errors.New("invalid key")
  }

  cBytes := (*C.uint8_t)(C.CBytes(cert))
  defer C.free(unsafe.Pointer(cBytes))

  success := C.peacemakr_key_add_certificate(k.key, cBytes, C.size_t(len(cert)))
  if !success {
    return errors.New("failed to get bytes from peacemakr key")
  }

  return nil
}

func (k *PeacemakrKey) ECDHKeygen(cipher SymmetricCipher, peerKey *PeacemakrKey) *PeacemakrKey {
	return &PeacemakrKey{
		key: C.peacemakr_key_dh_generate((C.symmetric_cipher)(cipher), k.key, peerKey.key),
	}
}

func (k *PeacemakrKey) HKDFKeygen(cipher SymmetricCipher, digest MessageDigestAlgorithm, keyID []byte) (*PeacemakrKey, error) {
	if !k.IsValid() {
		return nil, errors.New("invalid master key")
	}

	cBytes := (*C.uint8_t)(C.CBytes(keyID))
	defer C.free(unsafe.Pointer(cBytes))
	cNumBytes := (C.size_t)(len(keyID))
	return &PeacemakrKey{
		key: C.peacemakr_key_new_from_master((C.symmetric_cipher)(cipher), (C.message_digest_algorithm)(digest), k.key, cBytes, cNumBytes),
	}, nil
}

func (k *PeacemakrKey) Config() (CryptoConfig, error) {
	if !k.IsValid() {
		return CryptoConfig{}, errors.New("invalid key passed to GetKeyConfig")
	}

	keyConfig := C.peacemakr_key_get_config(k.key)
	return configFromInternal(keyConfig), nil
}

func (k *PeacemakrKey) Bytes() ([]byte, error) {
  if !k.IsValid() {
      return []byte{}, errors.New("invalid key passed to GetKeyConfig")
  }

	var buf *byte
  defer C.free(unsafe.Pointer(buf))
	var bufSize C.size_t

	success := C.peacemakr_key_get_bytes(k.key, (**C.uint8_t)(unsafe.Pointer(&buf)), (*C.size_t)(&bufSize))
	if !success {
		return []byte{}, errors.New("failed to get bytes from peacemakr key")
	}

	return C.GoBytes(unsafe.Pointer(buf), C.int(bufSize)), nil
}

func (k *PeacemakrKey) Certificate() ([]byte, error) {
  if !k.IsValid() {
      return nil, errors.New("invalid key passed to GetKeyConfig")
  }

  var buf *byte
  defer C.free(unsafe.Pointer(buf))
  var bufSize C.size_t

  success := C.peacemakr_key_to_certificate(k.key, (**C.char)(unsafe.Pointer(&buf)), (*C.size_t)(&bufSize))
  if !success {
    return nil, errors.New("failed to get certificate from peacemakr key")
  }

  return C.GoBytes(unsafe.Pointer(buf), C.int(bufSize)), nil
}

func (k *PeacemakrKey) Destroy() {
	if !k.IsValid() {
		return
	}
	C.peacemakr_key_free((*C.peacemakr_key_t)(k.key))
	k.key = nil
}

// ========================= Core APIs =========================

func Encrypt(key *PeacemakrKey, plaintext Plaintext, rand RandomDevice) (*CiphertextBlob, error) {
	if !key.IsValid() {
		return nil, errors.New("invalid key passed to Encrypt")
	}

	cPlaintext := plaintextToInternal(plaintext)
	defer freeInternalPlaintext(&cPlaintext)

	blob := C.peacemakr_encrypt(key.key, (*C.plaintext_t)(unsafe.Pointer(&cPlaintext)), (*C.random_device_t)(unsafe.Pointer(&rand.randomDevice)))

	if blob == nil {
		return nil, errors.New("encryption failed")
	}

	return &CiphertextBlob{
		blob: blob,
	}, nil
}

func GetPlaintextBlob(plaintext Plaintext) (*CiphertextBlob, error) {
  cPlaintext := plaintextToInternal(plaintext)
  defer freeInternalPlaintext(&cPlaintext)

  blob := C.peacemakr_get_plaintext_blob((*C.plaintext_t)(unsafe.Pointer(&cPlaintext)))
  if blob == nil {
    return nil, errors.New("unable to get plaintext blob")
  }

  return &CiphertextBlob{
    blob: blob,
  }, nil
}

func ExtractPlaintextFromBlob(blob *CiphertextBlob) (Plaintext, error) {
  var plaintext C.plaintext_t
  defer freeInternalPlaintext(&plaintext)

  if !C.peacemakr_extract_plaintext_blob(blob.blob, (*C.plaintext_t)(unsafe.Pointer(&plaintext))) {
    return Plaintext{}, errors.New("failed to extract plaintext blob")
  }

    // the C.GoBytes functions make copies of the underlying data so it's OK to free the original ptr
  return Plaintext{
    Data: C.GoBytes(unsafe.Pointer(plaintext.data), C.int(plaintext.data_len)),
    Aad:  C.GoBytes(unsafe.Pointer(plaintext.aad), C.int(plaintext.aad_len)),
  }, nil
}

func Serialize(digest MessageDigestAlgorithm, blob *CiphertextBlob) ([]byte, error) {
	var cSize C.size_t
	serialized := C.peacemakr_serialize((C.message_digest_algorithm)(digest), blob.blob, (*C.size_t)(unsafe.Pointer(&cSize)))
	if serialized == nil {
		return nil, errors.New("serialization failed")
	}
	return C.GoBytes(unsafe.Pointer(serialized), C.int(cSize)), nil
}

func Deserialize(serialized []byte) (*CiphertextBlob, *CryptoConfig, error) {
	cBlobBytes := C.CBytes(serialized)
	defer C.free(cBlobBytes)
	cBlobLen := C.size_t(len(serialized))

	cConfig := C.crypto_config_t{}

	deserialized := C.peacemakr_deserialize((*C.uint8_t)(cBlobBytes), cBlobLen, (*C.crypto_config_t)(unsafe.Pointer(&cConfig)))
	if deserialized == nil {
		return nil, nil, errors.New("deserialization failed")
	}

	outConfig := configFromInternal(cConfig)
	return &CiphertextBlob{
		blob: deserialized,
	}, &outConfig, nil
}

func Sign(senderKey *PeacemakrKey, plaintext Plaintext, digest MessageDigestAlgorithm, ciphertext *CiphertextBlob) error {
	if !senderKey.IsValid() {
		return errors.New("invalid key passed to Encrypt")
	}

	cPlaintext := plaintextToInternal(plaintext)
	defer freeInternalPlaintext(&cPlaintext)

	if !C.peacemakr_sign(senderKey.key, (*C.plaintext_t)(unsafe.Pointer(&cPlaintext)), (C.message_digest_algorithm)(digest), ciphertext.blob) {
	  return errors.New("signing failed")
	}

	return nil
}

func ExtractUnverifiedAAD(ciphertext []byte) ([]byte, error) {
	var plaintext C.plaintext_t
	defer freeInternalPlaintext(&plaintext)
	if ciphertext[len(ciphertext)-1] != 0 {
		ciphertext = append(ciphertext, byte(0)) // add NULL terminator
	}

	deserialized, _, err := Deserialize(ciphertext)
	if err != nil {
		return nil, err
	}

	extractSuccess := bool(C.peacemakr_get_unverified_aad(deserialized.blob, (*C.plaintext_t)(unsafe.Pointer(&plaintext))))
	if !extractSuccess {
		return nil, errors.New("extraction failed")
	}

	return C.GoBytes(unsafe.Pointer(plaintext.aad), C.int(plaintext.aad_len)), nil
}

type DecryptCode int
const (
	DECRYPT_SUCCESS       DecryptCode = 0
	DECRYPT_NEED_VERIFY   DecryptCode = 1
	DECRYPT_FAILED        DecryptCode = 2
)

func Decrypt(key *PeacemakrKey, ciphertext *CiphertextBlob) (*Plaintext, bool, error) {
	if !key.IsValid() {
		return nil, false, errors.New("invalid key passed to Decrypt")
	}

	var plaintext C.plaintext_t
	defer freeInternalPlaintext(&plaintext)

	decryptCode := DecryptCode(C.peacemakr_decrypt(key.key, ciphertext.blob, (*C.plaintext_t)(unsafe.Pointer(&plaintext))))
	if decryptCode == DECRYPT_FAILED {
		return nil, false, errors.New("decrypt failed")
	}

	needVerify := false
	if decryptCode == DECRYPT_NEED_VERIFY {
	    needVerify = true
	}

    // the C.GoBytes functions make copies of the underlying data so it's OK to free the original ptr
	return &Plaintext{
		Data: C.GoBytes(unsafe.Pointer(plaintext.data), C.int(plaintext.data_len)),
		Aad:  C.GoBytes(unsafe.Pointer(plaintext.aad), C.int(plaintext.aad_len)),
	}, needVerify, nil
}

func Verify(senderKey *PeacemakrKey, plaintext *Plaintext, ciphertext *CiphertextBlob) error {
	if !senderKey.IsValid() {
		return errors.New("invalid key passed to Encrypt")
	}

    cPlaintext := plaintextToInternal(*plaintext)
    defer freeInternalPlaintext(&cPlaintext)

	verified := C.peacemakr_verify(senderKey.key, (*C.plaintext_t)(unsafe.Pointer(&cPlaintext)), ciphertext.blob)
	if !verified {
		return errors.New("verification failed")
	}

	return nil
}

func HMAC(algo MessageDigestAlgorithm, key *PeacemakrKey, buf []byte) ([]byte, error) {
    if !key.IsValid() {
        return nil, errors.New("invalid key")
    }

    var outSize C.size_t
    hmac := C.peacemakr_hmac(C.message_digest_algorithm(algo), key.key, (*C.uint8_t)(C.CBytes(buf)), C.size_t(len(buf)), (*C.size_t)(unsafe.Pointer(&outSize)))
    if hmac == nil {
        return nil, errors.New("hmac failed")
    }

    return C.GoBytes(unsafe.Pointer(hmac), C.int(outSize)), nil

}
