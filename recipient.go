package dashi

import (
	"encoding/base64"
	"jjavery/dashi/internal/sodium"
)

type Recipient struct {
	PublicKey       []byte
	X25519PublicKey []byte
}

func NewRecipientFromPublicKeyString(publicKeyString string) (*Recipient, error) {
	publicKey, err := base64.RawStdEncoding.DecodeString(publicKeyString)
	if err != nil {
		return nil, err
	}

	x25519PublicKey, err := sodium.ConvertEd25519PublicKeyToX25519(publicKey)
	if err != nil {
		return nil, err
	}

	return &Recipient{
		PublicKey:       publicKey,
		X25519PublicKey: x25519PublicKey,
	}, nil
}
