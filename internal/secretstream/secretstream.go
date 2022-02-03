package secretstream

import (
	"bytes"
	"io"
	"jjavery/dashi/internal/chunked"
	"jjavery/dashi/internal/sodium"
)

const chunkSize = 256

type SecretStreamWriter struct {
	encoder       *sodium.SecretStreamEncoder
	chunkedWriter io.WriteCloser
	buf           bytes.Buffer
	chunkSize     int
	out           io.Writer
	err           error
}

func NewSecretStreamWriter(key []byte, chunkSize int, out io.Writer) (*SecretStreamWriter, error) {
	encoder, header, err := sodium.NewSecretStreamEncoder(key)
	if err != nil {
		return nil, err
	}

	chunkedWriter := chunked.NewChunkedWriter(out)

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

type SecretStreamReader struct {
	decoder       *sodium.SecretStreamDecoder
	chunkedReader io.Reader
	in            io.Reader
	buf           bytes.Buffer
	eof           bool
	err           error
}

func NewSecretStreamReader(key []byte, in io.Reader) (*SecretStreamReader, error) {
	chunkedReader := chunked.NewChunkedReader(in)

	header := make([]byte, 24)
	_, err := chunkedReader.Read(header)
	if err != nil {
		return nil, err
	}

	decoder, err := sodium.NewSecretStreamDecoder(key, header)
	if err != nil {
		return nil, err
	}

	reader := SecretStreamReader{
		decoder:       decoder,
		chunkedReader: chunkedReader,
		in:            in,
	}

	return &reader, nil
}

func (reader *SecretStreamReader) Read(p []byte) (int, error) {
	if reader.err != nil {
		return 0, reader.err
	}
	if reader.buf.Len() > 0 {
		return reader.buf.Read(p)
	}
	if reader.eof {
		return 0, io.EOF
	}

	chunk := make([]byte, chunkSize+17)

	l, err := reader.chunkedReader.Read(chunk)
	if err == io.EOF {
		reader.eof = true
	} else if err != nil {
		return 0, err
	}

	plaintext, err := reader.decoder.Decode(chunk[0:l])
	if err != nil {
		return 0, err
	}

	n := len(plaintext)
	if n < len(p) {
		copy(p, plaintext)
		return n, nil
	}

	_, err = reader.buf.Write(plaintext)
	if err != nil {
		return 0, err
	}

	n, err = reader.buf.Read(p)
	if err != nil {
		return n, err
	}

	return n, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
