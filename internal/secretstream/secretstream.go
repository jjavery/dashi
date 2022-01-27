package secretstream

import (
	"bytes"
	"encoding/binary"
	"io"
	"jjavery/dashi/internal/sodium"
)

type SecretStreamWriter struct {
	encoder   *sodium.SecretStreamEncoder
	buf       bytes.Buffer
	chunkSize int
	out       io.Writer
	err       error
}

func NewWriter(key []byte, chunkSize int, out io.Writer) (*SecretStreamWriter, error) {
	encoder, err := sodium.NewSecretStreamEncoder(key)
	if err != nil {
		return nil, err
	}

	header := encoder.Header()

	headerLength := make([]byte, 4)
	binary.BigEndian.PutUint32(headerLength, uint32(len(header)))

	_, err = out.Write(headerLength)
	if err != nil {
		return nil, err
	}

	_, err = out.Write(header)
	if err != nil {
		return nil, err
	}

	writer := SecretStreamWriter{
		encoder:   encoder,
		chunkSize: chunkSize,
		out:       out,
	}

	return &writer, nil
}

func (writer *SecretStreamWriter) Write(p []byte) (n int, err error) {
	if writer.err != nil {
		return 0, writer.err
	}
	if len(p) == 0 {
		return 0, nil
	}

	total := len(p)
	chunkSize := writer.chunkSize

	for written := 0; written < total; {
		write := min(total-written, chunkSize-writer.buf.Len())

		writer.buf.Write(p[written : written+write])

		written += write

		if writer.buf.Len() >= chunkSize && written < total {
			writer.err = writer.flush(false)
			if writer.err != nil {
				return 0, writer.err
			}
		}
	}

	return total, nil
}

func (writer *SecretStreamWriter) Close() error {
	if writer.err != nil {
		return writer.err
	}

	writer.err = writer.flush(true)

	return writer.err
}

func (writer *SecretStreamWriter) flush(final bool) error {
	chunk, err := writer.encoder.Encode(writer.buf.Bytes(), nil, final)
	if err != nil {
		writer.err = err
		return err
	}

	writer.buf.Reset()

	chunkLength := make([]byte, 4)
	binary.BigEndian.PutUint32(chunkLength, uint32(len(chunk)))

	_, writer.err = writer.out.Write(chunkLength)
	if writer.err != nil {
		return writer.err
	}

	_, writer.err = writer.out.Write(chunk)

	return writer.err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
