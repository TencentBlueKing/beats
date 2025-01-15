// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package readfile

import (
	"bytes"
	"io"

	"golang.org/x/text/encoding"
	"golang.org/x/text/transform"

	"github.com/elastic/beats/libbeat/common/streambuf"
	"github.com/elastic/beats/libbeat/logp"
)

const unlimited = 0

// lineReader reads lines from underlying reader, decoding the input stream
// using the configured codec. The reader keeps track of bytes consumed
// from raw input stream for every decoded line.
type LineReader struct {
	reader     io.Reader
	codec      encoding.Encoding
	bufferSize int
	maxBytes   int // max bytes per line limit to avoid OOM with malformatted files
	nl         []byte
	inBuffer   *streambuf.Buffer
	outBuffer  *streambuf.Buffer
	inOffset   int // input buffer read offset
	byteCount  int // number of bytes decoded from input buffer into output buffer
	decoder    transform.Transformer

	skippedByteCount int // number of bytes skipped, when the line is too long
	batchMode        bool
}

// New creates a new reader object
func NewLineReader(input io.Reader, config Config) (*LineReader, error) {
	encoder := config.Codec.NewEncoder()

	// Create newline char based on encoding
	nl, _, err := transform.Bytes(encoder, []byte{'\n'})
	if err != nil {
		return nil, err
	}

	return &LineReader{
		reader:     input,
		codec:      config.Codec,
		bufferSize: config.BufferSize,
		maxBytes:   config.MaxBytes,
		nl:         nl,
		decoder:    config.Codec.NewDecoder(),
		inBuffer:   streambuf.New(nil),
		outBuffer:  streambuf.New(nil),
		batchMode:  config.BatchMode,
	}, nil
}

// Next reads the next line until the new line character
func (r *LineReader) Next() ([]byte, int, error) {
	// This loop is need in case advance detects a line ending which turns out
	// not to be one when decoded. If that is the case, reading continues.
	for {
		// read next 'potential' line from input buffer/reader
		err := r.advance()
		if err != nil {
			if r.inBuffer.Len() == 0 || !(err.Error() == "file was removed" || err.Error() == "file inactive") {
				// buffer为空，或者不属于文件被删除以及文件不活跃的错误，直接返回空
				// return and reset consumed bytes count
				sz := r.byteCount
				r.byteCount = 0
				return nil, sz, err
			}

			logp.Info("LineReader get an advance err: %s, send all %d bytes in buffer", err, r.inBuffer.Len())
			// Found EOF and collectOnEOF is true
			// -> decode input sequence into outBuffer
			// let's take whole buffer len without len(nl) if it ends with it
			end := r.inBuffer.Len()
			if bytes.HasSuffix(r.inBuffer.Bytes(), r.nl) {
				end -= len(r.nl)
			}

			sz, err := r.decode(end, false)
			if err != nil {
				logp.Err("Error decoding line: %s", err)
				// In case of error increase size by unencoded length
				sz = r.inBuffer.Len()
			}

			// Consume transformed bytes from input buffer
			_ = r.inBuffer.Advance(sz)
			r.inBuffer.Reset()

			// continue scanning input buffer from last position + 1
			r.inOffset = end - sz
			if r.inOffset < 0 {
				// fix inOffset if '\n' has encoding > 8bits + firl line has been decoded
				r.inOffset = 0
			}
			// output buffer contains untile EOF. Extract
			// byte slice from buffer and reset output buffer.
			bytes, err := r.outBuffer.Collect(r.outBuffer.Len())
			r.outBuffer.Reset()
			if err != nil {
				// This should never happen as otherwise we have a broken state
				panic(err)
			}

			// return and reset consumed bytes count
			sz = r.byteCount
			r.byteCount = 0
			return bytes, sz, err

		}

		// Check last decoded byte really being '\n' also unencoded
		// if not, continue reading
		buf := r.outBuffer.Bytes()

		// This can happen if something goes wrong during decoding
		if len(buf) == 0 {
			logp.Err("Empty buffer returned by advance")
			continue
		}

		if buf[len(buf)-1] == '\n' {
			break
		} else {
			logp.Debug("line", "Line ending char found which wasn't one: %c", buf[len(buf)-1])
		}
	}

	// output buffer contains complete line ending with '\n'. Extract
	// byte slice from buffer and reset output buffer.
	bytes, err := r.outBuffer.Collect(r.outBuffer.Len())
	r.outBuffer.Reset()
	if err != nil {
		// This should never happen as otherwise we have a broken state
		panic(err)
	}

	// return and reset consumed bytes count
	sz := r.byteCount + r.skippedByteCount
	r.byteCount = 0
	r.skippedByteCount = 0
	return bytes, sz, nil
}

func (r *LineReader) findInBufferIndex(from int, seq []byte) int {
	if r.batchMode {
		return r.inBuffer.LastIndexFrom(from, seq)
	}
	return r.inBuffer.IndexFrom(from, seq)
}

// Reads from the buffer until a new line character is detected
// Returns an error otherwise
func (r *LineReader) advance() error {
	// Initial check if buffer has already a newLine character
	idx := r.findInBufferIndex(r.inOffset, r.nl)

	// fill inBuffer until '\n' sequence has been found in input buffer
	for idx == -1 {
		// increase search offset to reduce iterations on buffer when looping
		newOffset := r.inBuffer.Len() - len(r.nl)
		if newOffset > r.inOffset {
			r.inOffset = newOffset
		}

		buf := make([]byte, r.bufferSize)

		// try to read more bytes into buffer
		n, err := r.reader.Read(buf)

		// Appends buffer also in case of err
		r.inBuffer.Append(buf[:n])
		if err != nil {
			return err
		}

		// empty read => return buffer error (more bytes required error)
		if n == 0 {
			return streambuf.ErrNoMoreBytes
		}

		// Check if buffer has newLine character
		idx = r.findInBufferIndex(r.inOffset, r.nl)

		// 超出最大限制的长日志处理
		if r.maxBytes != 0 {
			// 如果已找到最后一个换行符索引位置，且超出最大限制，则找到第一行单独处理
			if idx != -1 && idx > r.maxBytes {
				var err error
				firstIdx := r.inBuffer.IndexFrom(r.inOffset, r.nl)
				if firstIdx > r.maxBytes {
					_, err = r.decode(r.maxBytes, true)
					r.skippedByteCount += firstIdx + len(r.nl) - r.maxBytes
				} else {
					_, err = r.decode(firstIdx+len(r.nl), false)
				}
				err = r.inBuffer.Advance(firstIdx + len(r.nl))
				r.inBuffer.Reset()
				r.inOffset = 0
				return err
			}
			// 如果未找到最后一个换行符索引位置，且超出最大限制，则分截断上报，仅处理最大限制字节数
			if idx == -1 && r.inBuffer.Len() > r.maxBytes {
				sz, err := r.decode(r.maxBytes, true)
				if err != nil {
					logp.Err("Error decoding line: %s", err)
					// In case of error increase size by unencoded length
					sz = r.maxBytes
				}
				err = r.inBuffer.Advance(sz)
				r.inBuffer.Reset()
				r.inOffset = 0

				// 跳过该行剩余字节
				skipped, err := r.skipUntilNewLine(buf)
				r.skippedByteCount += skipped
				return err
			}
		}
	}

	// found encoded byte sequence for '\n' in buffer
	// -> decode input sequence into outBuffer
	sz, err := r.decode(idx+len(r.nl), false)
	if err != nil {
		logp.Err("Error decoding line: %s", err)
		// In case of error increase size by unencoded length
		sz = idx + len(r.nl)
	}

	// consume transformed bytes from input buffer
	err = r.inBuffer.Advance(sz)
	r.inBuffer.Reset()

	// continue scanning input buffer from last position + 1
	r.inOffset = idx + 1 - sz
	if r.inOffset < 0 {
		// fix inOffset if '\n' has encoding > 8bits + firl line has been decoded
		r.inOffset = 0
	}

	return err
}

func (r *LineReader) skipUntilNewLine(buf []byte) (int, error) {
	// The length of the line skipped
	skipped := r.inBuffer.Len()

	// Clean up the buffer
	err := r.inBuffer.Advance(skipped)
	r.inBuffer.Reset()

	// Reset inOffset
	r.inOffset = 0

	if err != nil {
		return 0, err
	}

	// Read until the new line is found
	for idx := -1; idx == -1; {
		n, err := r.reader.Read(buf)

		// Check bytes read for newLine
		if n > 0 {
			idx = bytes.Index(buf[:n], r.nl)

			if idx != -1 {
				r.inBuffer.Append(buf[idx+len(r.nl) : n])
				skipped += idx + len(r.nl)
			} else {
				skipped += n
			}
		}

		if err != nil {
			return skipped, err
		}

		if n == 0 {
			return skipped, streambuf.ErrNoMoreBytes
		}
	}

	return skipped, nil
}

func (r *LineReader) decode(end int, addNl bool) (int, error) {
	var err error
	buffer := make([]byte, 1024)
	inBytes := r.inBuffer.Bytes()
	start := 0

	for start < end {
		var nDst, nSrc int

		nDst, nSrc, err = r.decoder.Transform(buffer, inBytes[start:end], false)
		if err != nil {
			// Check if error is different from destination buffer too short
			if err != transform.ErrShortDst {
				r.outBuffer.Write(inBytes[0:end])
				start = end
				break
			}

			// Reset error as decoding continues
			err = nil
		}

		start += nSrc
		r.outBuffer.Write(buffer[:nDst])
	}

	r.byteCount += start
	if addNl {
		r.outBuffer.Write(r.nl)
	}
	return start, err
}
