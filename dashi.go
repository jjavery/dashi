package dashi

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
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

	err = writeHeader(key, nonce, secretKey, publicKey, recipients, out)
	if err != nil {
		return err
	}

	lineWriter := linewrap.NewWriter([]byte("\r\n"), 80, out)

	encoder := base64.NewEncoder(base64.RawStdEncoding, lineWriter)

	writer, err := secretstream.NewWriter(key, chunkSize, encoder)
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

	_, err = io.WriteString(out, "\r\n\r\nSignature: "+b64(signature)+"\r\n")
	if err != nil {
		return err
	}

	return nil
}

func writeHeader(key []byte, nonce []byte, secretKey []byte, publicKey []byte, recipients []Recipient,
	out io.Writer) error {

	var header bytes.Buffer

	_, err := header.WriteString(magic + "\r\n")
	if err != nil {
		return err
	}

	_, err = header.WriteString("Public-Key: Ed25519 " + b64(publicKey) + "\r\n")
	if err != nil {
		return err
	}

	_, err = header.WriteString("Nonce: " + b64(nonce) + "\r\n")
	if err != nil {
		return err
	}

	for _, recipient := range recipients {
		publicKey, err := sodium.ConvertEd25519PublicKeyToX25519(recipient.PublicKey)
		if err != nil {
			return err
		}

		box, err := sodium.CreateBox(key, nonce, publicKey, secretKey)
		if err != nil {
			return err
		}

		_, err = header.WriteString("To: Ed25519 " + b64(box) + "\r\n")
		if err != nil {
			return err
		}

		incrementNonce(nonce)
	}

	headerLength := make([]byte, 4)
	binary.BigEndian.PutUint32(headerLength, uint32(header.Len()))

	_, err = header.WriteString("\r\n")
	if err != nil {
		return err
	}

	_, err = out.Write(header.Bytes())
	if err != nil {
		return err
	}

	return nil
}

func Decrypt(identities []Identity, in io.Reader, out io.Writer) error {
	// reader := bufio.NewReader(in)

	err := readMagic(in)
	if err != nil {
		return err
	}

	headerLength, err := readLength(in)
	if err != nil {
		return err
	}

	fmt.Println(headerLength)

	return nil
}

func readMagic(in io.Reader) error {

	return nil
}

func readLength(in io.Reader) (int, error) {
	b := make([]byte, 4)

	_, err := io.ReadFull(in, b)
	if err != nil {
		return 0, err
	}

	length := int(binary.BigEndian.Uint32(b))

	return length, nil
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
