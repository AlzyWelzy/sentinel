package apm

import (
	"compress/gzip"
	"io"
)

func newGzipReader(r io.Reader) (io.ReadCloser, error) { return gzip.NewReader(r) }
