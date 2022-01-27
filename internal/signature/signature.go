package signature

import (
	"io"
	"jjavery/dashi/internal/sodium"
)

type SignatureWriter struct {
	hash  *sodium.GenericHash
	out   io.Writer
	final []byte
	err   error
}

func NewWriter(key []byte, out io.Writer) (*SignatureWriter, error) {
	hash, err := sodium.NewGenericHash(key)
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

func (writer *SignatureWriter) Verify(secretKey []byte, signature []byte) (bool, error) {
	return false, nil
}
