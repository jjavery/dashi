package linewrap

import (
	"bytes"
	"io"
)

type LineWriter struct {
	delim     []byte
	buf       bytes.Buffer
	chunkSize int
	out       io.Writer
	err       error
}

func NewWriter(delim []byte, chunkSize int, out io.Writer) io.WriteCloser {
	writer := LineWriter{
		delim:     delim,
		chunkSize: chunkSize,
		out:       out,
	}

	return &writer
}

func (writer *LineWriter) Write(p []byte) (n int, err error) {
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

func (writer *LineWriter) Close() error {
	if writer.err != nil {
		return writer.err
	}

	writer.err = writer.flush(true)

	return writer.err
}

func (writer *LineWriter) flush(final bool) error {
	chunk := writer.buf.Bytes()

	writer.buf.Reset()

	_, writer.err = writer.out.Write(chunk)
	if writer.err != nil {
		return writer.err
	}

	if !final {
		_, writer.err = writer.out.Write(writer.delim)
	}

	return writer.err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
