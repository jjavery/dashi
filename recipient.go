package dashi

import "encoding/base64"

type Recipient struct {
	PublicKey []byte
}

func NewRecipient(keyString string) (*Recipient, error) {
	publicKey, err := base64.RawStdEncoding.DecodeString(keyString)
	if err != nil {
		return nil, err
	}

	return &Recipient{
		PublicKey: publicKey,
	}, nil
}
