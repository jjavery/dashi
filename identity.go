package dashi

import "encoding/base64"

type Identity struct {
	SecretKey []byte
}

func NewIdentity(keyString string) (*Identity, error) {
	secretKey, err := base64.RawStdEncoding.DecodeString(keyString)
	if err != nil {
		return nil, err
	}

	return &Identity{
		SecretKey: secretKey,
	}, nil
}
