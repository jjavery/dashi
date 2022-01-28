package header

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/textproto"
	"strings"
)

const protocolVersion = "DASHI/0.0.1"
const maxHeaderLength = 1024 * 1024

var b64 = base64.RawStdEncoding.EncodeToString
var b64d = base64.RawStdEncoding.DecodeString

type Header struct {
	ProtocolVersion string
	PublicKey       []byte
	EphemeralKey    []byte
	Nonce           []byte
	Recipients      []Recipient
	HMAC            []byte
}

type KeyType string

const (
	Ed25519 KeyType = "Ed25519"
	X25519  KeyType = "X25519"
)

type Recipient struct {
	KeyType KeyType
	ID      []byte
	Message []byte
}

func NewHeader(publicKey []byte, ephemeralKey []byte,
	nonce []byte, recipients []Recipient) (*Header, error) {

	header := Header{
		ProtocolVersion: protocolVersion,
		PublicKey:       publicKey,
		EphemeralKey:    ephemeralKey,
		Nonce:           nonce,
		Recipients:      recipients,
	}

	return &header, nil
}

func (header *Header) Marshal(out io.Writer) error {
	var buf bytes.Buffer

	_, err := buf.WriteString(header.ProtocolVersion)
	if err != nil {
		return err
	}

	_, err = buf.WriteString("\r\n")
	if err != nil {
		return err
	}

	_, err = buf.WriteString("Public-Key: Ed25519 ")
	if err != nil {
		return err
	}

	_, err = buf.WriteString(b64(header.PublicKey))
	if err != nil {
		return err
	}

	_, err = buf.WriteString("\r\n")
	if err != nil {
		return err
	}

	_, err = buf.WriteString("Ephemeral-Key: X25519 ")
	if err != nil {
		return err
	}

	_, err = buf.WriteString(b64(header.EphemeralKey))
	if err != nil {
		return err
	}

	_, err = buf.WriteString("\r\n")
	if err != nil {
		return err
	}

	_, err = buf.WriteString("Nonce: ")
	if err != nil {
		return err
	}

	_, err = buf.WriteString(b64(header.Nonce))
	if err != nil {
		return err
	}

	_, err = buf.WriteString("\r\n")
	if err != nil {
		return err
	}

	for _, recipient := range header.Recipients {
		recipient.Marshal(&buf)
	}

	_, err = buf.WriteString("\r\n")
	if err != nil {
		return err
	}

	out.Write(buf.Bytes())

	return nil
}

func NewRecipient(keyType KeyType, id []byte, message []byte) (*Recipient, error) {
	recipient := Recipient{
		KeyType: keyType,
		ID:      id,
		Message: message,
	}

	return &recipient, nil
}

func (recipient *Recipient) Marshal(out io.Writer) error {
	var buf bytes.Buffer

	_, err := buf.WriteString("Recipient: ")
	if err != nil {
		return err
	}

	_, err = buf.WriteString(string(recipient.KeyType))
	if err != nil {
		return err
	}

	if recipient.ID != nil {
		_, err = buf.WriteString(" ")
		if err != nil {
			return err
		}

		_, err = buf.WriteString(b64(recipient.ID))
		if err != nil {
			return err
		}
	}

	_, err = buf.WriteString("\r\n  ")
	if err != nil {
		return err
	}

	_, err = buf.WriteString(b64(recipient.Message))
	if err != nil {
		return err
	}

	_, err = buf.WriteString("\r\n")
	if err != nil {
		return err
	}

	out.Write(buf.Bytes())

	return nil
}

func Parse(in io.Reader) (*Header, io.Reader, error) {
	limit := io.LimitReader(in, maxHeaderLength)
	buf := bufio.NewReader(limit)

	// Read the protocol version line (first line)
	protocolVersionLine, err := buf.ReadString('\n')
	if err != nil {
		return nil, nil, err
	}
	protocolVersionLine = strings.TrimRight(protocolVersionLine, "\r\n")
	if protocolVersionLine != protocolVersion {
		return nil, nil, fmt.Errorf("unknown protocol version")
	}

	// Use a textproto.Reader to read the rest of the header (awesome!)
	tpReader := textproto.NewReader(buf)

	mimeHeader, err := tpReader.ReadMIMEHeader()
	if err != nil {
		return nil, nil, err
	}

	overread, err := buf.Peek(buf.Buffered())
	if err != nil {
		return nil, nil, err
	}

	body := io.MultiReader(bytes.NewReader(overread), in)

	// Public Key
	publicKeyHeader := mimeHeader.Get("Public-Key")
	if publicKeyHeader == "" {
		return nil, nil, fmt.Errorf("Public-Key: header is required")
	}

	publicKeyHeaderFields := strings.Fields(publicKeyHeader)
	if len(publicKeyHeaderFields) != 2 {
		return nil, nil, fmt.Errorf("Public-Key: invalid format")
	}
	if publicKeyHeaderFields[0] != string(Ed25519) {
		return nil, nil, fmt.Errorf("Public-Key: unknown key type")
	}
	if len(publicKeyHeaderFields[1]) != 43 {
		return nil, nil, fmt.Errorf("Public-Key: invalid length")
	}

	publicKey, err := b64d(publicKeyHeaderFields[1])
	if err != nil {
		return nil, nil, fmt.Errorf("Public-Key: %v", err)
	}

	// Public Key
	ephemeralKeyHeader := mimeHeader.Get("Ephemeral-Key")
	if ephemeralKeyHeader == "" {
		return nil, nil, fmt.Errorf("Ephemeral-Key: header is required")
	}

	ephemeralKeyHeaderFields := strings.Fields(ephemeralKeyHeader)
	if len(ephemeralKeyHeaderFields) != 2 {
		return nil, nil, fmt.Errorf("Ephemeral-Key: invalid format")
	}
	if ephemeralKeyHeaderFields[0] != string(X25519) {
		return nil, nil, fmt.Errorf("Ephemeral-Key: unknown key type")
	}
	if len(ephemeralKeyHeaderFields[1]) != 43 {
		return nil, nil, fmt.Errorf("Ephemeral-Key: invalid length")
	}

	ephemeralKey, err := b64d(ephemeralKeyHeaderFields[1])
	if err != nil {
		return nil, nil, fmt.Errorf("Ephemeral-Key: %v", err)
	}

	// Nonce
	nonceHeader := mimeHeader.Get("Nonce")
	if nonceHeader == "" {
		return nil, nil, fmt.Errorf("Nonce: header is required")
	}
	if len(nonceHeader) != 32 {
		return nil, nil, fmt.Errorf("Nonce: invalid length")
	}

	nonce, err := b64d(nonceHeader)
	if err != nil {
		return nil, nil, fmt.Errorf("Nonce: %v", err)
	}

	// Recipients
	recipientHeaders := mimeHeader.Values("Recipient")
	if len(recipientHeaders) == 0 {
		return nil, nil, fmt.Errorf("Recipient: header is required")
	}

	var recipients []Recipient

	for _, recipientHeader := range recipientHeaders {
		if recipientHeader == "" {
			return nil, nil, fmt.Errorf("Recipient: header is required")
		}

		recipientHeaderFields := strings.Fields(recipientHeader)
		l := len(recipientHeaderFields)
		if l < 2 || l > 3 {
			return nil, nil, fmt.Errorf("Recipient: invalid format")
		}
		if recipientHeaderFields[0] != string(Ed25519) {
			return nil, nil, fmt.Errorf("Recipient: unknown key type")
		}
		var recipientHeaderID, recipientHeaderMessage string
		switch l {
		case 2:
			recipientHeaderMessage = recipientHeaderFields[1]
		case 3:
			recipientHeaderID = recipientHeaderFields[1]
			recipientHeaderMessage = recipientHeaderFields[2]

			if len(recipientHeaderID) != 43 {
				return nil, nil, fmt.Errorf("Recipient: invalid id length")
			}
		}
		if len(recipientHeaderMessage) != 64 {
			return nil, nil, fmt.Errorf("Recipient: invalid message length")
		}

		recipientID, err := b64d(recipientHeaderID)
		if err != nil {
			return nil, nil, fmt.Errorf("Recipient: %v", err)
		}

		recipientMessage, err := b64d(recipientHeaderMessage)
		if err != nil {
			return nil, nil, fmt.Errorf("Recipient: %v", err)
		}

		recipient, err := NewRecipient(Ed25519, recipientID, recipientMessage)
		if err != nil {
			return nil, nil, fmt.Errorf("Recipient: %v", err)
		}

		recipients = append(recipients, *recipient)
	}

	header := Header{
		ProtocolVersion: protocolVersionLine,
		PublicKey:       publicKey,
		EphemeralKey:    ephemeralKey,
		Nonce:           nonce,
		Recipients:      recipients,
	}

	return &header, body, nil
}
