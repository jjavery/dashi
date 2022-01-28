package secretstream

import (
	"bytes"
	"io"
	"jjavery/dashi/internal/chunked"
	"jjavery/dashi/internal/sodium"
)

type SecretStreamWriter struct {
	encoder       *sodium.SecretStreamEncoder
	chunkedWriter io.WriteCloser
	buf           bytes.Buffer
	chunkSize     int
	out           io.Writer
	err           error
}

func NewSecretStreamWriter(key []byte, chunkSize int, out io.Writer) (*SecretStreamWriter, error) {
	encoder, err := sodium.NewSecretStreamEncoder(key)
	if err != nil {
		return nil, err
	}

	chunkedWriter := chunked.NewChunkedWriter(out)

	header := encoder.Header()

	_, err = chunkedWriter.Write(header)
	if err != nil {
		return nil, err
	}

	writer := SecretStreamWriter{
		encoder:       encoder,
		chunkedWriter: chunkedWriter,
		chunkSize:     chunkSize,
		out:           out,
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
		toWrite := min(total-written, chunkSize-writer.buf.Len())

		writer.buf.Write(p[written : written+toWrite])

		written += toWrite

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

	_, writer.err = writer.chunkedWriter.Write(chunk)
	if writer.err != nil {
		return writer.err
	}

	if final {
		writer.err = writer.chunkedWriter.Close()
	}

	return writer.err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
