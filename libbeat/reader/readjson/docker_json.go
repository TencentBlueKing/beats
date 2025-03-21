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

package readjson

import (
	"bytes"
	"runtime"
	"time"

	"github.com/pkg/errors"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/reader"
	"github.com/mailru/easyjson"
)

// DockerJSONReader processor renames a given field
type DockerJSONReader struct {
	reader reader.Reader
	// stream filter, `all`, `stderr` or `stdout`
	stream string

	// join partial lines
	partial bool

	// Force log format: json-file | cri
	forceCRI bool

	// parse CRI flags
	criflags bool

	// batch mode
	batchMode bool

	stripNewLine func([]byte) []byte

	lineBuffer      []byte
	lineBufferBytes int

	totalBytes   int
	maxBytes     int
	lineFinished bool
}

type LogLine struct {
	Partial   bool      `json:"-"`
	Timestamp time.Time `json:"-"`
	Time      string    `json:"time"`
	Stream    string    `json:"stream"`
	Log       string    `json:"log"`
}

// New creates a new reader renaming a field
func New(r reader.Reader, stream string, partial bool, forceCRI bool, CRIFlags bool, batchMode bool, maxBytes int) *DockerJSONReader {
	reader := DockerJSONReader{
		stream:       stream,
		partial:      partial,
		reader:       r,
		forceCRI:     forceCRI,
		criflags:     CRIFlags,
		batchMode:    batchMode,
		maxBytes:     maxBytes,
		lineFinished: false,
	}

	if runtime.GOOS == "windows" {
		reader.stripNewLine = stripNewLineWin
	} else {
		reader.stripNewLine = stripNewLine
	}

	return &reader
}

// parseCRILog parses logs in CRI log format.
// CRI log format example :
// 2017-09-12T22:32:21.212861448Z stdout 2017-09-12 22:32:21.212 [INFO][88] table.go 710: Invalidating dataplane cache
func (p *DockerJSONReader) parseCRILog(message *reader.Message, msg *LogLine) error {
	split := 3
	// read line tags if split is enabled:
	if p.criflags {
		split = 4
	}

	// current field
	i := 0

	// timestamp
	log := bytes.SplitN(message.Content, []byte{' '}, split)
	if len(log) < split {
		return errors.New("invalid CRI log format")
	}
	ts, err := time.Parse(time.RFC3339, string(log[i]))
	if err != nil {
		return errors.Wrap(err, "parsing CRI timestamp")
	}
	message.Ts = ts
	i++

	// stream
	msg.Stream = string(log[i])
	i++

	// tags
	partial := false
	if p.criflags {
		// currently only P(artial) or F(ull) are available
		tags := bytes.Split(log[i], []byte{':'})
		for _, tag := range tags {
			if len(tag) == 1 && tag[0] == 'P' {
				partial = true
			}
		}
		i++
	}

	msg.Partial = partial
	message.AddFields(common.MapStr{
		"stream": msg.Stream,
	})
	// Remove \n ending for partial messages
	message.Content = log[i]
	if partial {
		message.Content = p.stripNewLine(message.Content)
	}

	return nil
}

// parseReaderLog parses logs in Docker JSON log format.
// Docker JSON log format example:
// {"log":"1:M 09 Nov 13:27:36.276 # User requested shutdown...\n","stream":"stdout"}
func (p *DockerJSONReader) parseDockerJSONLog(message *reader.Message, msg *LogLine) error {
	err := easyjson.Unmarshal(message.Content, msg)

	if err != nil {
		return errors.Wrap(err, "decoding docker JSON")
	}

	// Parse timestamp
	ts, err := time.Parse(time.RFC3339, msg.Time)
	if err != nil {
		return errors.Wrap(err, "parsing docker timestamp")
	}

	message.AddFields(common.MapStr{
		"stream": msg.Stream,
	})
	message.Content = []byte(msg.Log)
	message.Ts = ts
	msg.Partial = message.Content[len(message.Content)-1] != byte('\n')

	return nil
}

func (p *DockerJSONReader) parseLine(message *reader.Message, msg *LogLine) error {
	if p.forceCRI {
		return p.parseCRILog(message, msg)
	}

	// If froceCRI isn't set, autodetect file type
	if len(message.Content) > 0 && message.Content[0] == '{' {
		return p.parseDockerJSONLog(message, msg)
	}

	return p.parseCRILog(message, msg)
}

// parseCRILog parses logs in CRI log format.
// CRI log format example :
// 2017-09-12T22:32:21.212861448Z stdout 2017-09-12 22:32:21.212 [INFO][88] table.go 710: Invalidating dataplane cache
func (p *DockerJSONReader) batchParseCRILog(content []byte, msg *LogLine) ([]byte, error) {
	split := 3
	// read line tags if split is enabled:
	if p.criflags {
		split = 4
	}

	// current field
	i := 0

	log := bytes.SplitN(content, []byte{' '}, split)
	if len(log) < split {
		return nil, errors.New("invalid CRI log format")
	}
	_, err := time.Parse(time.RFC3339, string(log[i]))
	if err != nil {
		return nil, errors.Wrap(err, "parsing CRI timestamp")
	}
	i++

	// stream
	msg.Stream = string(log[i])
	i++

	// tags
	partial := false
	if p.criflags {
		// currently only P(artial) or F(ull) are available
		tags := bytes.Split(log[i], []byte{':'})
		for _, tag := range tags {
			if len(tag) == 1 && tag[0] == 'P' {
				partial = true
			}
		}
		i++
	}

	msg.Partial = partial

	// Remove \n ending for partial messages
	content = log[i]
	if partial {
		content = p.stripNewLine(content)
	}

	return content, nil
}

// parseReaderLog parses logs in Docker JSON log format.
// Docker JSON log format example:
// {"log":"1:M 09 Nov 13:27:36.276 # User requested shutdown...\n","stream":"stdout"}
func (p *DockerJSONReader) batchParseDockerJSONLog(content []byte, msg *LogLine) ([]byte, error) {
	err := easyjson.Unmarshal(content, msg)

	if err != nil {
		return nil, errors.Wrap(err, "decoding docker JSON")
	}

	// Parse timestamp
	_, err = time.Parse(time.RFC3339, msg.Time)
	if err != nil {
		return nil, errors.Wrap(err, "parsing docker timestamp")
	}

	content = []byte(msg.Log)
	msg.Partial = content[len(content)-1] != byte('\n')

	return content, nil
}

func (p *DockerJSONReader) batchParseLine(content []byte, msg *LogLine) ([]byte, error) {
	if p.forceCRI {
		return p.batchParseCRILog(content, msg)
	}

	// If froceCRI isn't set, autodetect file type
	if len(content) > 0 && content[0] == '{' {
		return p.batchParseDockerJSONLog(content, msg)
	}

	return p.batchParseCRILog(content, msg)
}

// Next returns the next line.
func (p *DockerJSONReader) Next() (reader.Message, error) {
	if p.batchMode {
		return p.batchNext()
	}
	return p.next()
}

func (p *DockerJSONReader) next() (reader.Message, error) {
	var nbytes int
	p.lineFinished = false
	for {
		message, err := p.reader.Next()

		// keep the right bytes count even if we return an error
		nbytes += message.Bytes
		message.Bytes = nbytes

		if err != nil {
			return message, err
		}

		var logLine LogLine
		err = p.parseLine(&message, &logLine)
		if err != nil {
			return message, err
		}

		// Handle multiline messages, join partial lines
		for p.partial && logLine.Partial {
			next, err := p.reader.Next()

			// keep the right bytes count even if we return an error
			nbytes += next.Bytes
			message.Bytes = nbytes

			if err != nil {
				return message, err
			}
			err = p.parseLine(&next, &logLine)
			if err != nil {
				return message, err
			}
			// 当行buffer与当前msg内容相加超过最大字节数，将buffer中的内容截断返回
			if len(message.Content)+len(next.Content) > p.maxBytes {
				// 计算截断位置
				truncateIdx := p.maxBytes - len(message.Content)
				// 未截断部分写入texts，清空缓冲区
				message.Content = append(message.Content, next.Content[:truncateIdx]...)
				p.lineFinished = true
				reader.LinesTruncated.Add(1)
			}
			if !p.lineFinished {
				message.Content = append(message.Content, next.Content...)
			}
		}

		if p.stream != "all" && p.stream != logLine.Stream {
			continue
		}

		return message, err
	}
}

func (p *DockerJSONReader) batchNext() (reader.Message, error) {

	for {

		message, err := p.reader.Next()

		message.Bytes += p.totalBytes
		p.totalBytes = message.Bytes

		if err != nil {
			return message, err
		}

		buffer := message.Content

		texts := make([][]byte, 0, bytes.Count(buffer, []byte{'\n'})+1)

		// 当前位置
		var offset int
		for offset < len(buffer) {
			// 继续解析下一行日志
			idx := bytes.Index(buffer[offset:], []byte{'\n'})

			if idx == -1 {
				idx = len(buffer[offset:])
			} else {
				idx += 1
			}

			var logLine LogLine

			// json解析前原始日志
			rawContent := buffer[offset : offset+idx]
			content, err := p.batchParseLine(rawContent, &logLine)

			// 指针往前推移
			offset += idx

			if err != nil {
				// 失败的行直接跳过
				continue
			}

			if p.partial && logLine.Partial {
				// 本行日志还没结束，继续读取
				if p.lineBuffer == nil {
					p.lineBuffer = make([]byte, 0, len(content)*4)
				}
				// 当行buffer与当前msg内容相加超过最大字节数，将buffer中的内容截断返回
				if len(p.lineBuffer)+len(content) > p.maxBytes {
					// 计算截断位置
					truncateIdx := p.maxBytes - len(p.lineBuffer)

					// 未截断部分写入texts，清空缓冲区
					texts = append(texts, append(p.lineBuffer, content[:truncateIdx]...))

					// 清空缓冲区，此行标记为返回结束
					p.lineBuffer = nil
					p.lineBufferBytes = 0
					p.lineFinished = true
					reader.LinesTruncated.Add(1)
				} else if !p.lineFinished {
					p.lineBuffer = append(p.lineBuffer, content...)
					p.lineBufferBytes += idx
				}
				continue
			}

			if p.stream == "all" || p.stream == logLine.Stream {
				if !p.lineFinished {
					if len(p.lineBuffer)+len(content) > p.maxBytes {
						// 计算截断位置
						truncateIdx := p.maxBytes - len(p.lineBuffer)

						// 未截断部分写入texts，清空缓冲区
						texts = append(texts, append(p.lineBuffer, content[:truncateIdx]...))

						// 清空缓冲区，此行标记为读取结束
						p.lineFinished = true
						reader.LinesTruncated.Add(1)
					} else {
						texts = append(texts, append(p.lineBuffer, content...))
					}
				}
			}

			// 行日志已经结束，直接清空缓存
			p.lineFinished = false
			p.lineBuffer = nil
			p.lineBufferBytes = 0
		}

		if len(texts) > 0 {
			// 如果text已经有数据，就发送
			message.Content = bytes.Join(texts, nil)

			// 消息大小追加上一次没有消耗完的部分
			message.Bytes -= p.lineBufferBytes
			p.totalBytes -= message.Bytes
			return message, nil
		}

	}
}

func stripNewLine(content []byte) []byte {
	l := len(content)
	if l > 0 && content[l-1] == '\n' {
		content = content[:l-1]
	}
	return content
}

func stripNewLineWin(content []byte) []byte {
	content = bytes.TrimRightFunc(content, func(r rune) bool {
		return r == '\n' || r == '\r'
	})
	return content
}
