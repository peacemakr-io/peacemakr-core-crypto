package peacemakr_core_crypto

// #cgo LDFLAGS: -lpeacemakr-core-crypto -lssl -lcrypto -L/usr/local/lib
// #cgo CFLAGS: -I${SRCDIR}/../../../../core/include
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
*/
import "C"
import (
	"crypto/rand"
	"unsafe"
	"fmt"
)

//export go_rng
func go_rng(buf *C.uchar, size C.size_t) C.int {
	var randomBytes = make([]byte, size)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return 1
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
	}
	return nil
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
	AES_128_GCM       SymmetricCipher = 0
	AES_192_GCM       SymmetricCipher = 1
	AES_256_GCM       SymmetricCipher = 2
	CHACHA20_POLY1305 SymmetricCipher = 3
)

type AsymmetricCipher int

const (
	NONE     AsymmetricCipher = 0
	RSA_2048 AsymmetricCipher = 1
	RSA_4096 AsymmetricCipher = 2
	//EC25519       AsymmetricCipher = 3
)

type MessageDigestAlgorithm int

const (
	SHA_224 MessageDigestAlgorithm = 0
	SHA_256 MessageDigestAlgorithm = 1
	SHA_384 MessageDigestAlgorithm = 2
	SHA_512 MessageDigestAlgorithm = 3
)

type EncryptionMode int

const (
	SYMMETRIC  EncryptionMode = 0
	ASYMMETRIC EncryptionMode = 1
)

type CryptoConfig struct {
	mode             EncryptionMode
	symmetricCipher  SymmetricCipher
	asymmetricCipher AsymmetricCipher
	digestAlgorithm  MessageDigestAlgorithm
}

func configToInternal(config CryptoConfig) C.crypto_config_t {
	return C.crypto_config_t{
		mode:             C.encryption_mode(config.mode),
		symm_cipher:      C.symmetric_cipher(config.symmetricCipher),
		asymm_cipher:     C.asymmetric_cipher(config.asymmetricCipher),
		digest_algorithm: C.message_digest_algorithm(config.digestAlgorithm),
	}
}

type Plaintext struct {
	data []byte
	aad  []byte
}

func plaintextToInternal(plaintext Plaintext) C.plaintext_t {
	return C.plaintext_t{
		data_len: C.size_t(len(plaintext.data)),
		data:     (*C.uchar)(C.CBytes(plaintext.data)),
		aad_len:  C.size_t(len(plaintext.aad)),
		aad:      (*C.uchar)(C.CBytes(plaintext.aad)),
	}
}

func freeInternalPlaintext(internalPlaintext C.plaintext_t) {
	C.free(unsafe.Pointer(internalPlaintext.data))
	C.free(unsafe.Pointer(internalPlaintext.aad))
}

type CiphertextBlob struct {
	blob *C.ciphertext_blob_t
}

type PeacemakrKey struct {
	key *C.peacemakr_key_t
}

func NewPeacemakrKey(config CryptoConfig, rand RandomDevice) PeacemakrKey {
	return PeacemakrKey{
		key: C.PeacemakrKey_new(configToInternal(config), (*C.random_device_t)(unsafe.Pointer(&rand.randomDevice))),
	}
}

func NewPeacemakrKeyFromBytes(config CryptoConfig, contents []byte) PeacemakrKey {
	cBytes := (*C.uchar)(C.CBytes(contents))
	defer C.free(unsafe.Pointer(cBytes))
	return PeacemakrKey{
		key: C.PeacemakrKey_new_bytes(configToInternal(config), cBytes),
	}
}

func DestroyPeacemakrKey(key PeacemakrKey) {
	C.PeacemakrKey_free((*C.peacemakr_key_t)(key.key))
}

func Encrypt(cfg CryptoConfig, key PeacemakrKey, plaintext Plaintext, rand RandomDevice) CiphertextBlob {
	cPlaintext := plaintextToInternal(plaintext)
	defer freeInternalPlaintext(cPlaintext)

	return CiphertextBlob{
		C.encrypt(configToInternal(cfg), key.key, (*C.plaintext_t)(unsafe.Pointer(&cPlaintext)), (*C.random_device_t)(unsafe.Pointer(&rand.randomDevice))),
	}
}

func Decrypt(key PeacemakrKey, ciphertext CiphertextBlob) (Plaintext, bool) {
	var plaintext C.plaintext_t
	defer freeInternalPlaintext(plaintext)

	out := C.decrypt(key.key, ciphertext.blob, (*C.plaintext_t)(unsafe.Pointer(&plaintext)))

	return Plaintext{
		data: C.GoBytes(unsafe.Pointer(plaintext.data), C.int(plaintext.data_len)),
		aad:  C.GoBytes(unsafe.Pointer(plaintext.aad), C.int(plaintext.aad_len)),
	}, bool(out)
}

func Serialize(blob CiphertextBlob) []byte {
	var cSize C.size_t
	serialized := C.serialize_blob(blob.blob, (*C.size_t)(unsafe.Pointer(&cSize)))
	fmt.Println(cSize)
	return C.GoBytes(unsafe.Pointer(serialized), C.int(cSize))
}

func Deserialize(serialized []byte) CiphertextBlob {
	cBlobBytes := C.CBytes(serialized)
	defer C.free(cBlobBytes)
	cBlobLen := C.size_t(len(serialized))
	fmt.Println(cBlobLen)
	deserialized := C.deserialize_blob((*C.uchar)(cBlobBytes), cBlobLen)
	return CiphertextBlob{
		blob: deserialized,
	}
}
