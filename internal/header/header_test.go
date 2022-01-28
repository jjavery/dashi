package header_test

import (
	"bytes"
	"encoding/base64"
	"jjavery/dashi/internal/header"
	"strings"
	"testing"
)

var b64d = base64.RawStdEncoding.DecodeString

var publicKey, _ = b64d("N0wckSAp9AaWXp8LoLDatNZwImCruEXR+8c3bU0/Yd8")
var ephemeralKey, _ = b64d("s7ZwQdPm5UXTW3ZF8lbSq0S6IxYTAghdh7oYrL1oIxU")
var nonce, _ = b64d("wodOop+GzLQcONxsXpvcASDAXJZ6qoF6")
var recipientID, _ = b64d("58Jrd91MvzPqJEVty1ZBfqBwFyfdS31Eee48irrKSjw")
var recipientMessage, _ = b64d("JMFadsWkBfDkR6YRS+XhLcTdcmeGomXpN1nep29nG/co9/a2uf3phMCL190eag9C")

var headerString = strings.ReplaceAll(`DASHI/0.0.1
Public-Key: Ed25519 N0wckSAp9AaWXp8LoLDatNZwImCruEXR+8c3bU0/Yd8
Ephemeral-Key: X25519 s7ZwQdPm5UXTW3ZF8lbSq0S6IxYTAghdh7oYrL1oIxU
Nonce: wodOop+GzLQcONxsXpvcASDAXJZ6qoF6
Recipient: Ed25519 58Jrd91MvzPqJEVty1ZBfqBwFyfdS31Eee48irrKSjw
  JMFadsWkBfDkR6YRS+XhLcTdcmeGomXpN1nep29nG/co9/a2uf3phMCL190eag9C
Recipient: Ed25519
  JMFadsWkBfDkR6YRS+XhLcTdcmeGomXpN1nep29nG/co9/a2uf3phMCL190eag9C

`, "\n", "\r\n")

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

	header, err := header.NewHeader(publicKey, ephemeralKey, nonce, recipients)
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
		if r.ID != nil && len(r.ID) != 0 {
			if bytes.Compare(r.ID, recipientID) != 0 {
				t.Errorf("expected:\n%q\nactual:\n%q\n", recipientID, r.ID)
			}
		}
		if bytes.Compare(r.Message, recipientMessage) != 0 {
			t.Errorf("expected:\n%q\nactual:\n%q\n", recipientMessage, r.Message)
		}
	}
}
