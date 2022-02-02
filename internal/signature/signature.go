package signature

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"io"
	"jjavery/dashi/internal/sodium"
	"strings"
	"unicode"
)

var b64 = base64.RawStdEncoding.EncodeToString
var b64d = base64.RawStdEncoding.DecodeString

type SignatureWriter struct {
	hash  *sodium.GenericHash
	out   io.Writer
	final []byte
	err   error
}

func NewSignatureWriter(out io.Writer) (*SignatureWriter, error) {
	hash, err := sodium.NewGenericHash(nil)
	if err != nil {
		return nil, err
	}

	writer := SignatureWriter{
		hash: hash,
		out:  out,
	}

	return &writer, nil
}

func (writer *SignatureWriter) Write(p []byte) (n int, err error) {
	if writer.err != nil {
		return 0, writer.err
	}
	if len(p) == 0 {
		return 0, nil
	}

	writer.err = writer.hash.Update(p)
	if writer.err != nil {
		return 0, writer.err
	}

	_, writer.err = writer.out.Write(p)
	if writer.err != nil {
		return 0, writer.err
	}

	return len(p), nil
}

func (writer *SignatureWriter) Close() error {
	if writer.err != nil {
		return writer.err
	}

	writer.final, writer.err = writer.hash.Final()

	return writer.err
}

func (writer *SignatureWriter) Sign(secretKey []byte) ([]byte, error) {
	signature, err := sodium.SignDetached(writer.final, secretKey)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func (writer *SignatureWriter) Verify(publicKey []byte, signature []byte) (bool, error) {
	return false, nil
}

func (writer *SignatureWriter) Marshal(secretKey []byte, publicKey []byte, out io.Writer) error {
	// out := writer.out

	signature, err := sodium.SignDetached(writer.final, secretKey)
	if err != nil {
		return err
	}

	encSig := b64(signature)
	encSigLen := len(encSig)
	lineLen := encSigLen / (encSigLen/74 + 1)

	_, err = io.WriteString(out, "Signature:")
	// _, err = io.WriteString(out, "Signature: Ed25519 ")
	// if err != nil {
	// 	return err
	// }

	// _, err = io.WriteString(out, b32(publicKey))
	// if err != nil {
	// 	return err
	// }

	_, err = io.WriteString(out, "\r\n")
	if err != nil {
		return err
	}

	for i := 0; i < encSigLen; i += lineLen {
		_, err = io.WriteString(out, "  ")
		if err != nil {
			return err
		}

		_, err = io.WriteString(out, encSig[i:min(i+lineLen, encSigLen)])
		if err != nil {
			return err
		}

		_, err = io.WriteString(out, "\r\n")
		if err != nil {
			return err
		}
	}

	return nil
}

const maxSignatureLen = 1024
const signatureReaderBufferLen = 1024 * 32

type SignatureReader struct {
	hash      *sodium.GenericHash
	in        *bufio.Reader
	final     []byte
	signature []byte
	err       error
}

func NewSignatureReader(in io.Reader) (*SignatureReader, error) {
	hash, err := sodium.NewGenericHash(nil)
	if err != nil {
		return nil, err
	}

	reader := SignatureReader{
		hash: hash,
		in:   bufio.NewReader(in),
	}

	return &reader, nil
}

func (reader *SignatureReader) Read(p []byte) (n int, err error) {
	if reader.err != nil {
		return 0, reader.err
	}

	var eof = false
	n = len(p) + maxSignatureLen

	var peek []byte

	peek, reader.err = reader.in.Peek(n)
	if len(peek) < n {
		// EOF coming up. Check for a signature at the end
		delimiter := []byte("Signature:")
		i := bytes.LastIndex(peek, delimiter)
		s := peek[(i + len(delimiter)):]
		reader.signature, reader.err = b64d(stripSpaces(string(s)))
		if reader.err != nil {
			return 0, reader.err
		}
		p = p[:i]
		eof = true
	} else if reader.err != nil {
		return 0, reader.err
	}

	n, reader.err = reader.in.Read(p)
	if reader.err != nil {
		return n, reader.err
	}

	reader.err = reader.hash.Update(p)
	if reader.err != nil {
		return n, reader.err
	}

	if eof {
		reader.final, reader.err = reader.hash.Final()
		if reader.err != nil {
			return n, reader.err
		}

		reader.err = io.EOF

		return n, reader.err
	}

	return n, nil
}

func (reader *SignatureReader) Verify(publicKey []byte) (bool, error) {
	return sodium.VerifyDetached(reader.signature, reader.final, publicKey)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func stripSpaces(str string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, str)
}
