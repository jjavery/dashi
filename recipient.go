package dashi

import (
	"jjavery/dashi/internal/sodium"
)

type Recipient struct {
	PublicKey       []byte
	X25519PublicKey []byte
}

func NewRecipientFromPublicKeyString(publicKeyString string) (*Recipient, error) {
	publicKey, err := b32d(publicKeyString)
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

func (recipient *Recipient) String() string {
	return b32(recipient.PublicKey)
}
