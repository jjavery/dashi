package header_test

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"jjavery/dashi/internal/header"
	"strings"
	"testing"
)

var b64d = base64.RawStdEncoding.DecodeString
var b32d = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString

var publicKey, _ = b32d("XUESSUZJTCPJT7THPA4TSRM6EQ32HVY57COGWVZCRVXXNSMGMCNA")
var secretKey, _ = b32d("PSC5XDCRXXT47CBYWWOQM2ZMMGKDR562XXQOV52HGDM7CW3VHSJ32CJJKMUZRHUZ7ZTXQOJZIWPCIN5D24O7RHDLK4RI233WZGDGBGQ")
var ephemeralKey, _ = b64d("N3LqVa4YeQhkwOyGR8L49lI3aSkj0pQghSiZ/AuuoRg")
var nonce, _ = b64d("gN2Wfzgk4GA+KI4GThTO3+mUIeHyt0jc")
var recipientID, _ = b32d("XUESSUZJTCPJT7THPA4TSRM6EQ32HVY57COGWVZCRVXXNSMGMCNA")
var recipientMessage, _ = b64d("PU9JZcrrvdsjyT0bpAG98nqsy1qMiH/ulEi894IwLnriUtFRY1G/T3MuGqoRAZBZ")

var headerString = strings.ReplaceAll(`DASHI/0.1
Public-Key: Ed25519 XUESSUZJTCPJT7THPA4TSRM6EQ32HVY57COGWVZCRVXXNSMGMCNA
Ephemeral-Key: X25519 N3LqVa4YeQhkwOyGR8L49lI3aSkj0pQghSiZ/AuuoRg
Nonce: gN2Wfzgk4GA+KI4GThTO3+mUIeHyt0jc
Recipient: Ed25519 XUESSUZJTCPJT7THPA4TSRM6EQ32HVY57COGWVZCRVXXNSMGMCNA
  PU9JZcrrvdsjyT0bpAG98nqsy1qMiH/ulEi894IwLnriUtFRY1G/T3MuGqoRAZBZ
Recipient: Ed25519
  PU9JZcrrvdsjyT0bpAG98nqsy1qMiH/ulEi894IwLnriUtFRY1G/T3MuGqoRAZBZ
Signature:
  FgFRmnTdlJ1kqRoxX4eeiFuVqEOMPpsPWIM3doLDw9p
  muEnncttG2lfa8TsAmM7ERttE6U5wE2lrLmmWeh0YCg

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

	header.Marshal(secretKey, buf)
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
