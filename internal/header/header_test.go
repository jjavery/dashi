package header_test

import (
	"bytes"
	"jjavery/dashi/internal/header"
	"strings"
	"testing"
)

var publicKey = make([]byte, 32)
var nonce = make([]byte, 24)
var recipientID = make([]byte, 32)
var recipientMessage = make([]byte, 48)

var headerString = "DASHI/0.0.1\r\n" +
	"Public-Key: Ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n" +
	"Nonce: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n" +
	"Recipient: Ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n" +
	"  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n" +
	"Recipient: Ed25519\r\n" +
	"  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n" +
	"\r\n"

func TestHeaderMarshal(t *testing.T) {
	recipient1, err := header.NewRecipient(header.Ed25519, recipientID, recipientMessage)
	if err != nil {
		t.Error(err)
	}

	recipient2, err := header.NewRecipient(header.Ed25519, nil, recipientMessage)
	if err != nil {
		t.Error(err)
	}

	recipients := []header.Recipient{*recipient1, *recipient2}

	header, err := header.NewHeader(publicKey, nonce, recipients)
	if err != nil {
		t.Error(err)
	}

	buf := &bytes.Buffer{}

	header.Marshal(buf)
	if err != nil {
		t.Error(err)
	}

	expected := headerString

	if buf.String() != expected {
		t.Errorf("expected:\n%q\nactual:\n%q\n", expected, buf.String())
	}
}

func TestHeaderParse(t *testing.T) {
	in := strings.NewReader(headerString)

	h, _, err := header.Parse(in)
	if err != nil {
		t.Error(err)
	}

	if h == nil {
		t.Error("expected header to not be nil")
	}
	if h.ProtocolVersion != "DASHI/0.0.1" {
		t.Errorf("unexpected protocol version: %q", h.ProtocolVersion)
	}
	if bytes.Compare(h.PublicKey, publicKey) != 0 {
		t.Errorf("expected:\n%q\nactual:\n%q\n", publicKey, h.PublicKey)
	}
	if bytes.Compare(h.Nonce, nonce) != 0 {
		t.Errorf("expected:\n%q\nactual:\n%q\n", nonce, h.Nonce)
	}
	if len(h.Recipients) != 2 {
		t.Error("expected recipients length to be 2")
	}
	for _, r := range h.Recipients {
		if r.KeyType != header.Ed25519 {
			t.Errorf("expected:\n%q\nactual:\n%q\n", header.Ed25519, r.KeyType)
		}
		if r.ID != nil {
			if bytes.Compare(r.ID, recipientID) != 0 {
				t.Errorf("expected:\n%q\nactual:\n%q\n", recipientID, r.ID)
			}
		}
		if bytes.Compare(r.Message, recipientMessage) != 0 {
			t.Errorf("expected:\n%q\nactual:\n%q\n", recipientMessage, r.Message)
		}
	}
}
