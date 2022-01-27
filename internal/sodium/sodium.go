package sodium

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"fmt"
	"unsafe"
)

func init() {
	result := C.sodium_init()
	if result != 0 {
		panic(fmt.Sprintf("libsodium initialization failed, result code %d",
			result))
	}
}

var signPublicKeyBytes = int(C.crypto_sign_publickeybytes())

func ConvertEd25519SecretKeyToPublicKey(ed25519SecretKey []byte) ([]byte, error) {
	publicKey := make([]byte, signPublicKeyBytes)

	result := C.crypto_sign_ed25519_sk_to_pk(
		(*C.uchar)(&publicKey[0]), (*C.uchar)(&ed25519SecretKey[0]))
	if result != 0 {
		return nil, fmt.Errorf("crypto_sign_ed25519_sk_to_pk: error %d", result)
	}

	return publicKey, nil
}

var secretstreamKeyBytes = int(C.crypto_secretstream_xchacha20poly1305_keybytes())

func CreateSecretstreamKey() []byte {
	key := make([]byte, secretstreamKeyBytes)

	C.crypto_secretstream_xchacha20poly1305_keygen((*C.uchar)(&key[0]))

	return key
}

var secretboxNonceBytes = int(C.crypto_secretbox_noncebytes())

func CreateSecretboxNonce() []byte {
	nonce := make([]byte, secretboxNonceBytes)

	C.randombytes_buf(unsafe.Pointer(&nonce[0]), C.ulong(secretboxNonceBytes))

	return nonce
}

var boxSecretKeyBytes = int(C.crypto_box_secretkeybytes())

func ConvertEd25519SecretKeyToX25519(ed25519SecretKey []byte) ([]byte, error) {
	secretKey := make([]byte, boxSecretKeyBytes)

	result := C.crypto_sign_ed25519_sk_to_curve25519(
		(*C.uchar)(&secretKey[0]),
		(*C.uchar)(&ed25519SecretKey[0]))
	if result != 0 {
		return nil, fmt.Errorf("crypto_sign_ed25519_sk_to_curve25519: error %d", result)
	}

	return secretKey, nil
}

var boxPublicKeyBytes = int(C.crypto_box_publickeybytes())

func ConvertEd25519PublicKeyToX25519(ed25519PublicKey []byte) ([]byte, error) {
	publicKey := make([]byte, boxPublicKeyBytes)

	result := C.crypto_sign_ed25519_pk_to_curve25519(
		(*C.uchar)(&publicKey[0]),
		(*C.uchar)(&ed25519PublicKey[0]))
	if result != 0 {
		return nil, fmt.Errorf("crypto_sign_ed25519_pk_to_curve25519: error %d", result)
	}

	return publicKey, nil
}

var boxMacBytes = int(C.crypto_box_macbytes())

func CreateBox(message []byte, nonce []byte, publicKey []byte,
	secretKey []byte) ([]byte, error) {

	mlen := len(message)
	box := make([]byte, boxMacBytes+mlen)

	result := C.crypto_box_easy(
		(*C.uchar)(&box[0]),
		(*C.uchar)(&message[0]),
		C.ulonglong(mlen),
		(*C.uchar)(&nonce[0]),
		(*C.uchar)(&publicKey[0]),
		(*C.uchar)(&secretKey[0]))
	if result != 0 {
		return nil, fmt.Errorf("crypto_box_easy: error %d", result)
	}

	return box, nil
}

var signBytes = int(C.crypto_sign_bytes())

func SignDetached(message []byte, secretKey []byte) ([]byte, error) {
	sig := make([]byte, signBytes)
	var siglen C.ulonglong

	result := C.crypto_sign_detached((*C.uchar)(&sig[0]), &siglen,
		(*C.uchar)(&message[0]), C.ulonglong(len(message)),
		(*C.uchar)(&secretKey[0]))
	if result != 0 {
		return nil, fmt.Errorf("crypto_box_easy: error %d", result)
	}

	return sig, nil
}

var genericHashBytes = int(C.crypto_generichash_bytes())

type GenericHash struct {
	state C.crypto_generichash_state
}

func NewGenericHash(key []byte) (*GenericHash, error) {
	hash := GenericHash{}

	result := C.crypto_generichash_init(
		&hash.state, (*C.uchar)(&key[0]), (C.size_t)(len(key)), (C.size_t)(genericHashBytes))
	if result != 0 {
		return nil, fmt.Errorf("crypto_generichash_init: error %d", result)
	}

	return &hash, nil
}

func (hash *GenericHash) Update(in []byte) error {
	result := C.crypto_generichash_update(
		&hash.state, (*C.uchar)(&in[0]), C.ulonglong(len(in)))
	if result != 0 {
		return fmt.Errorf("crypto_generichash_update: error %d", result)
	}

	return nil
}

func (hash *GenericHash) Final() ([]byte, error) {
	out := make([]byte, genericHashBytes)

	result := C.crypto_generichash_final(
		&hash.state, (*C.uchar)(&out[0]), (C.ulong)(len(out)))
	if result != 0 {
		return nil, fmt.Errorf("crypto_generichash_final: error %d", result)
	}

	return out, nil
}

var aBytes = int(C.crypto_secretstream_xchacha20poly1305_abytes())
var headerBytes = int(C.crypto_secretstream_xchacha20poly1305_headerbytes())
var stateBytes = int(C.crypto_secretstream_xchacha20poly1305_statebytes())
var tagMessage = C.crypto_secretstream_xchacha20poly1305_tag_message()
var tagFinal = C.crypto_secretstream_xchacha20poly1305_tag_final()

type SecretStreamEncoder struct {
	header []byte
	state  C.crypto_secretstream_xchacha20poly1305_state
}

func NewSecretStreamEncoder(key []byte) (*SecretStreamEncoder, error) {
	encoder := SecretStreamEncoder{
		header: make([]byte, headerBytes),
	}

	result := C.crypto_secretstream_xchacha20poly1305_init_push(
		&encoder.state,
		(*C.uchar)(&encoder.header[0]),
		(*C.uchar)(&key[0]))
	if result != 0 {
		return nil, fmt.Errorf("crypto_secretstream_xchacha20poly1305_init_push: error %d", result)
	}

	return &encoder, nil
}

func (encoder *SecretStreamEncoder) Header() []byte {
	return encoder.header
}

func (encoder *SecretStreamEncoder) Encode(p []byte, ad []byte, final bool) ([]byte, error) {
	mp, ml := plen(p)
	c := make([]byte, ml+aBytes)
	cp, _ := plen(c)
	adp, adl := plen(ad)

	tag := tagMessage
	if final {
		tag = tagFinal
	}

	result := C.crypto_secretstream_xchacha20poly1305_push(
		&encoder.state,
		(*C.uchar)(cp),
		(*C.ulonglong)(nil),
		(*C.uchar)(mp),
		(C.ulonglong)(ml),
		(*C.uchar)(adp),
		(C.ulonglong)(adl),
		tag)

	if result != 0 {
		return nil, fmt.Errorf("crypto_secretstream_xchacha20poly1305_push: error %d", result)
	}

	return c, nil
}

func plen(b []byte) (unsafe.Pointer, int) {
	if len(b) > 0 {
		return unsafe.Pointer(&b[0]), len(b)
	} else {
		return nil, 0
	}
}
