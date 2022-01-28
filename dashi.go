package dashi

import (
	"compress/zlib"
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

func Encrypt(identity Identity, recipients []Recipient,
	in io.Reader, out io.Writer) error {

	key := sodium.CreateSecretstreamKey()
	nonce := sodium.CreateSecretboxNonce()
	secretKey, err := sodium.ConvertEd25519SecretKeyToX25519(identity.SecretKey)
	if err != nil {
		return err
	}
	publicKey, err := sodium.ConvertEd25519SecretKeyToPublicKey(identity.SecretKey)
	if err != nil {
		return err
	}

	var headerRecipients []header.Recipient

	for _, recipient := range recipients {
		publicKey, err := sodium.ConvertEd25519PublicKeyToX25519(recipient.PublicKey)
		if err != nil {
			return err
		}

		box, err := sodium.CreateBox(key, nonce, publicKey, secretKey)
		if err != nil {
			return err
		}

		headerRecipient, err := header.NewRecipient(header.Ed25519, publicKey, box)
		if err != nil {
			return err
		}

		headerRecipients = append(headerRecipients, *headerRecipient)

		incrementNonce(nonce)
	}

	header, err := header.NewHeader(publicKey, nonce, headerRecipients)
	if err != nil {
		return err
	}

	header.Marshal(out)

	lineWriter := linewrap.NewWriter([]byte("\r\n"), 66, out)

	encoder := base64.NewEncoder(base64.RawStdEncoding, lineWriter)

	writer, err := secretstream.NewSecretStreamWriter(key, chunkSize, encoder)
	if err != nil {
		return err
	}

	compress := zlib.NewWriter(writer)

	sign, err := signature.NewWriter(key, compress)
	if err != nil {
		return err
	}

	_, err = io.Copy(sign, in)
	if err != nil {
		return err
	}

	err = sign.Close()
	if err != nil {
		return err
	}

	err = compress.Close()
	if err != nil {
		return err
	}

	err = writer.Close()
	if err != nil {
		return err
	}

	err = encoder.Close()
	if err != nil {
		return err
	}

	err = lineWriter.Close()
	if err != nil {
		return err
	}

	signature, err := sign.Sign(secretKey)
	if err != nil {
		return err
	}

	_, err = io.WriteString(out, "\r\n\r\nSignature:\r\n  "+b64(signature)+"\r\n")
	if err != nil {
		return err
	}

	return nil
}

func Decrypt(identities []Identity, in io.Reader, out io.Writer) error {

	header, body, err := header.Parse(in)
	if err != nil {
		return err
	}

	fmt.Println(header)

	_, err = io.Copy(out, body)
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
