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

//go:build !integration
// +build !integration

package console

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/common/fmtstr"
	"github.com/elastic/beats/libbeat/outputs"
	"github.com/elastic/beats/libbeat/outputs/codec"
	"github.com/elastic/beats/libbeat/outputs/codec/format"
	"github.com/elastic/beats/libbeat/outputs/codec/json"
	"github.com/elastic/beats/libbeat/outputs/outest"
	"github.com/elastic/beats/libbeat/publisher"
)

// capture stdout and return captured string
func withStdout(fn func()) (string, error) {
	stdout := os.Stdout

	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}

	os.Stdout = w
	defer func() {
		os.Stdout = stdout
	}()

	outC := make(chan string)
	go func() {
		// capture all output
		var buf bytes.Buffer
		_, err = io.Copy(&buf, r)
		r.Close()
		outC <- buf.String()
	}()

	fn()
	w.Close()
	result := <-outC
	return result, err
}

// TODO: add tests with other formatstr codecs

func TestConsoleOutput(t *testing.T) {
	tests := []struct {
		title    string
		codec    codec.Codec
		events   []beat.Event
		expected string
	}{
		{
			"single json event (pretty=false)",
			json.New("1.2.3", json.Config{
				Pretty:     false,
				EscapeHTML: false,
			}),
			[]beat.Event{
				{Fields: event("field", "value")},
			},
			"{\"@timestamp\":\"0001-01-01T00:00:00.000Z\",\"@metadata\":{\"beat\":\"test\",\"type\":\"_doc\",\"version\":\"1.2.3\"},\"field\":\"value\"}\n",
		},
		{
			"single json event (pretty=true)",
			json.New("1.2.3", json.Config{
				Pretty:     true,
				EscapeHTML: false,
			}),
			[]beat.Event{
				{Fields: event("field", "value")},
			},
			"{\n  \"@timestamp\": \"0001-01-01T00:00:00.000Z\",\n  \"@metadata\": {\n    \"beat\": \"test\",\n    \"type\": \"_doc\",\n    \"version\": \"1.2.3\"\n  },\n  \"field\": \"value\"\n}\n",
		},
		// TODO: enable test after update fmtstr support to beat.Event
		{
			"event with custom format string",
			format.New(fmtstr.MustCompileEvent("%{[event]}")),
			[]beat.Event{
				{Fields: event("event", "myevent")},
			},
			"myevent\n",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.title, func(t *testing.T) {
			batch := outest.NewBatch(test.events...)
			lines, err := run(test.codec, batch)
			assert.Nil(t, err)
			assert.Equal(t, test.expected, lines)

			// check batch correctly signalled
			if !assert.Len(t, batch.Signals, 1) {
				return
			}
			assert.Equal(t, outest.BatchACK, batch.Signals[0].Tag)
		})
	}
}

func run(codec codec.Codec, batches ...publisher.Batch) (string, error) {
	return withStdout(func() {
		c, _ := newConsole("test", outputs.NewNilObserver(), codec)
		for _, b := range batches {
			c.Publish(b)
		}
	})
}

func event(k, v string) common.MapStr {
	return common.MapStr{k: v}
}

type failingCodec struct {
	err error
}

func (c failingCodec) Encode(string, *beat.Event) ([]byte, error) {
	return nil, c.err
}

func collectConsoleError(t *testing.T) <-chan error {
	t.Helper()
	errCh := make(chan error, 4)
	SetErrorHandler(func(err error) {
		select {
		case errCh <- err:
		default:
		}
	})
	t.Cleanup(func() { SetErrorHandler(nil) })
	return errCh
}

func TestConsoleNotifiesEncodeFailure(t *testing.T) {
	errCh := collectConsoleError(t)
	batch := outest.NewBatch(beat.Event{Fields: event("field", "value")})
	c := &console{
		codec:    failingCodec{errors.New("encode failed")},
		observer: outputs.NewNilObserver(),
		writer:   bufio.NewWriterSize(io.Discard, 8*1024),
		index:    "test",
	}

	require.NoError(t, c.Publish(batch))
	if !assert.Len(t, batch.Signals, 1) {
		return
	}
	assert.Equal(t, outest.BatchACK, batch.Signals[0].Tag)

	select {
	case err := <-errCh:
		assert.Contains(t, err.Error(), "encoding failed")
		assert.Contains(t, err.Error(), "encode failed")
	default:
		t.Fatal("console encode failure was not reported")
	}
}

func TestConsoleNotifiesFlushFailure(t *testing.T) {
	errCh := collectConsoleError(t)

	r, w, err := os.Pipe()
	require.NoError(t, err)
	require.NoError(t, r.Close())

	batch := outest.NewBatch(beat.Event{Fields: event("field", "value")})
	c := &console{
		out:      w,
		codec:    json.New("1.2.3", json.Config{}),
		observer: outputs.NewNilObserver(),
		writer:   bufio.NewWriterSize(w, 8*1024),
		index:    "test",
	}
	t.Cleanup(func() { w.Close() })

	require.NoError(t, c.Publish(batch))
	if !assert.Len(t, batch.Signals, 1) {
		return
	}
	assert.Equal(t, outest.BatchACK, batch.Signals[0].Tag)

	select {
	case err := <-errCh:
		assert.Contains(t, err.Error(), "flush failed")
	default:
		t.Fatal("console flush failure was not reported")
	}
}

func TestConsoleWithoutErrorHandlerKeepsOriginalBehavior(t *testing.T) {
	SetErrorHandler(nil)

	batch := outest.NewBatch(beat.Event{Fields: event("field", "value")})
	c := &console{
		codec:    failingCodec{errors.New("encode failed")},
		observer: outputs.NewNilObserver(),
		writer:   bufio.NewWriterSize(io.Discard, 8*1024),
		index:    "test",
	}

	assert.NotPanics(t, func() {
		assert.NoError(t, c.Publish(batch))
	})
	if assert.Len(t, batch.Signals, 1) {
		assert.Equal(t, outest.BatchACK, batch.Signals[0].Tag)
	}
}
