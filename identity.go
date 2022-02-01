package dashi

import (
	"jjavery/dashi/internal/sodium"
)

type Identity struct {
	SecretKey       []byte
	PublicKey       []byte
	X25519SecretKey []byte
	X25519PublicKey []byte
}

func NewIdentity() (*Identity, error) {
	secretKey, publicKey, err := sodium.CreateSignKeypair()
	if err != nil {
		return nil, err
	}

	return NewIdentityFromKeyPair(secretKey, publicKey)
}

func NewIdentityFromSecretKeyString(secretKeyString string) (*Identity, error) {
	secretKey, err := b32d(secretKeyString)
	if err != nil {
		return nil, err
	}

	publicKey, err := sodium.ConvertEd25519SecretKeyToPublicKey(secretKey)
	if err != nil {
		return nil, err
	}

	return NewIdentityFromKeyPair(secretKey, publicKey)
}

func NewIdentityFromKeyPair(secretKey []byte, publicKey []byte) (*Identity, error) {
	x25519SecretKey, err := sodium.ConvertEd25519SecretKeyToX25519(secretKey)
	if err != nil {
		return nil, err
	}

	x25519PublicKey, err := sodium.ConvertEd25519PublicKeyToX25519(publicKey)
	if err != nil {
		return nil, err
	}

	return &Identity{
		SecretKey:       secretKey,
		PublicKey:       publicKey,
		X25519SecretKey: x25519SecretKey,
		X25519PublicKey: x25519PublicKey,
	}, nil
}

func (identity *Identity) String() string {
	return b32(identity.PublicKey)
}

func (identity *Identity) SecrectKeyString() string {
	return b32(identity.SecretKey)
}
