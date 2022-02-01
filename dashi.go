package dashi

import (
	"bytes"
	"compress/gzip"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"io"
	"jjavery/dashi/internal/header"
	"jjavery/dashi/internal/linewrap"
	"jjavery/dashi/internal/secretstream"
	"jjavery/dashi/internal/signature"
	"jjavery/dashi/internal/sodium"
)

const chunkSize = 256

var magic = "DASHI/0.1"
var b64 = base64.RawStdEncoding.EncodeToString
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString
var b32d = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString

func GenerateKey(out io.Writer) error {
	identity, err := NewIdentity()
	if err != nil {
		return err
	}

	io.WriteString(out, fmt.Sprintf("Public-Key: Ed25519 %s\r\n", identity.String()))
	io.WriteString(out, fmt.Sprintf("Secret-Key: Ed25519 %s\r\n", identity.SecrectKeyString()))

	return nil
}

func Encrypt(identity Identity, recipients []Recipient,
	in io.Reader, out io.Writer) error {

	key := sodium.CreateSecretstreamKey()
	ephemeral, err := NewIdentity()
	if err != nil {
		return err
	}
	nonce := sodium.CreateSecretboxNonce()
	boxNonce := make([]byte, len(nonce))
	copy(boxNonce, nonce)

	var headerRecipients []header.Recipient

	for _, recipient := range recipients {

		box, err := sodium.CreateBox(key, boxNonce, recipient.X25519PublicKey, ephemeral.X25519SecretKey)
		if err != nil {
			return err
		}

		headerRecipient, err := header.NewRecipient(header.Ed25519, recipient.PublicKey, box)
		if err != nil {
			return err
		}

		headerRecipients = append(headerRecipients, *headerRecipient)

		incrementNonce(boxNonce)
	}

	header, err := header.NewHeader(identity.PublicKey, ephemeral.X25519PublicKey, nonce, headerRecipients)
	if err != nil {
		return err
	}

	sign, err := signature.NewSignatureWriter(out)
	if err != nil {
		return err
	}

	header.Marshal(identity.SecretKey, sign)

	linewrap := linewrap.NewLineWriter("\r\n", 76, sign)

	encode := base64.NewEncoder(base64.RawStdEncoding, linewrap)

	var encryptTo io.Writer = sign
	if true {
		encryptTo = encode
	}

	encrypt, err := secretstream.NewSecretStreamWriter(key, chunkSize, encryptTo)
	if err != nil {
		return err
	}

	compress := gzip.NewWriter(encrypt)

	innerSign, err := signature.NewSignatureWriter(compress)
	if err != nil {
		return err
	}

	_, err = io.Copy(innerSign, in)
	if err != nil {
		return err
	}

	err = innerSign.Close()
	if err != nil {
		return err
	}

	innerSign.Marshal(identity.SecretKey, identity.PublicKey, compress)

	err = compress.Close()
	if err != nil {
		return err
	}

	err = encrypt.Close()
	if err != nil {
		return err
	}

	err = encode.Close()
	if err != nil {
		return err
	}

	err = linewrap.Close()
	if err != nil {
		return err
	}

	err = sign.Close()
	if err != nil {
		return err
	}

	_, err = io.WriteString(out, "\r\n\r\n")
	if err != nil {
		return err
	}

	sign.Marshal(identity.SecretKey, identity.PublicKey, out)

	return nil
}

func Decrypt(identities []Identity, in io.Reader, out io.Writer) error {

	header, body, err := header.Parse(in)
	if err != nil {
		return err
	}

	var key []byte
	// publicKey := header.PublicKey
	ephemeralKey := header.EphemeralKey
	nonce := header.Nonce
	boxNonce := make([]byte, len(nonce))
	copy(boxNonce, nonce)

	for _, recipient := range header.Recipients {
		for _, identity := range identities {
			id := recipient.ID
			if id != nil && bytes.Compare(id, identity.PublicKey) != 0 {
				continue
			}

			box := recipient.Message

			key, err = sodium.OpenBox(box, boxNonce, ephemeralKey, identity.X25519SecretKey)
			if err != nil {
				continue
			}
			break
		}

		if key != nil {
			break
		}

		incrementNonce(boxNonce)
	}

	if key == nil || len(key) == 0 {
		return fmt.Errorf("can't decrypt: no identity matches recipient(s)")
	}

	decode := base64.NewDecoder(base64.RawStdEncoding, body)

	decrypt, err := secretstream.NewSecretStreamReader(key, decode)
	if err != nil {
		return err
	}

	decompress, err := gzip.NewReader(decrypt)
	if err != nil {
		return err
	}

	readSig, err := signature.NewSignatureReader(decompress)
	if err != nil {
		return err
	}

	_, err = io.Copy(out, readSig)
	if err != nil {
		return err
	}

	return nil
}

func incrementNonce(nonce []byte) {
	for i := len(nonce) - 1; i >= 0; i-- {
		nonce[i]++

		if nonce[i] != 0 {
			break
		}

		if i == 0 {
			for j := range nonce {
				nonce[j] = 0
			}
		}
	}
}

func Sign(identity Identity, in io.Reader, out io.Writer) (err error) {

	return err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
