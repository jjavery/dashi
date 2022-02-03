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
	secretKey []byte
	hash      *sodium.SignHash
	out       io.Writer
	signature []byte
	err       error
}

func NewSignatureWriter(secretKey []byte, out io.Writer) (*SignatureWriter, error) {
	hash, err := sodium.NewSignHash()
	if err != nil {
		return nil, err
	}

	writer := SignatureWriter{
		secretKey: secretKey,
		hash:      hash,
		out:       out,
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

	n, writer.err = writer.write(p)

	return n, writer.err
}

func (writer *SignatureWriter) write(p []byte) (n int, err error) {
	err = writer.hash.Update(p)
	if err != nil {
		return 0, err
	}

	return writer.out.Write(p)
}

func (writer *SignatureWriter) Close() error {
	if writer.err != nil {
		return writer.err
	}

	writer.err = writer.close()

	return writer.err
}

func (writer *SignatureWriter) close() (err error) {
	writer.signature, err = writer.hash.Final(writer.secretKey)
	if err != nil {
		return err
	}

	return writer.marshal()
}

func (writer *SignatureWriter) marshal() error {
	out := writer.out

	encSig := b64(writer.signature)
	encSigLen := len(encSig)
	lineLen := encSigLen / (encSigLen/74 + 1)

	_, err := io.WriteString(out, "Signature:")
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
const signatureReaderBufferLen = 1024*32 + maxSignatureLen

type SignatureReader struct {
	hash      *sodium.SignHash
	in        *bufio.Reader
	in2       io.Reader
	buf       []byte
	signature []byte
	err       error
}

func NewSignatureReader(in io.Reader) (*SignatureReader, error) {
	hash, err := sodium.NewSignHash()
	if err != nil {
		return nil, err
	}

	reader := SignatureReader{
		in:   bufio.NewReaderSize(in, signatureReaderBufferLen),
		in2:  in,
		buf:  make([]byte, signatureReaderBufferLen),
		hash: hash,
	}

	return &reader, nil
}

func (reader *SignatureReader) Read(p []byte) (n int, err error) {
	if reader.err != nil {
		return 0, reader.err
	}

	n, reader.err = reader.read(p)

	return n, reader.err
}

func (reader *SignatureReader) read2(p []byte) (n int, err error) {
	n, err = reader.in2.Read(reader.buf)

	copy(p, reader.buf[:n])

	return n, err
}

func (reader *SignatureReader) read(p []byte) (n int, err error) {
	var eof = false
	n = min(signatureReaderBufferLen, len(p)+maxSignatureLen)

	var peek []byte

	peek, err = reader.in.Peek(n)
	if len(peek) < n && err == io.EOF {
		// EOF coming up. Check for a signature at the end
		delimiter := []byte("Signature:")
		i := bytes.LastIndex(peek, delimiter)
		s := peek[(i + len(delimiter)):]
		reader.signature, err = b64d(stripSpaces(string(s)))
		if err != nil {
			return 0, err
		}
		p = p[:i]
		eof = true
	} else if err != nil {
		return 0, err
	}

	n, err = reader.in.Read(p)
	if err != nil {
		return n, err
	}

	err = reader.hash.Update(p)
	if err != nil {
		return n, err
	}

	if eof {
		return n, io.EOF
	}

	return n, nil
}

func (reader *SignatureReader) Verify(publicKey []byte) (bool, error) {
	return reader.hash.Verify(reader.signature, publicKey)
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
