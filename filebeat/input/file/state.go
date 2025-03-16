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

package file

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mitchellh/hashstructure"

	"github.com/elastic/beats/libbeat/common/file"
)

// Identifier how to identify same file in the registry
const (
	IdentifierPath      = "path"
	IdentifierInodePath = "inode_path"
	IdentifierInode     = "inode"
)

// State is used to communicate the reading state of a file
type State struct {
	Id             string            `json:"-"` // local unique id to make comparison more efficient
	Finished       bool              `json:"-"` // harvester state
	Fileinfo       os.FileInfo       `json:"-"` // the file info
	FileIdentifier string            `json:"-"` // file identifier
	Source         string            `json:"source"`
	Offset         int64             `json:"offset"`
	Timestamp      time.Time         `json:"timestamp"`
	TTL            time.Duration     `json:"ttl"`
	Type           string            `json:"type"`
	Meta           map[string]string `json:"meta"`
	FileStateOS    file.StateOS
}

// NewState creates a new file state
func NewState(fileInfo os.FileInfo, path string, t string, meta map[string]string, fileIdentifier string) State {
	if len(meta) == 0 {
		meta = nil
	}
	return State{
		Fileinfo:       fileInfo,
		FileIdentifier: fileIdentifier,
		Source:         path,
		Finished:       false,
		FileStateOS:    file.GetOSState(fileInfo),
		Timestamp:      time.Now(),
		TTL:            -1, // By default, state does have an infinite ttl
		Type:           t,
		Meta:           meta,
	}
}

// ID returns a unique id for the state as a string
func (s *State) ID() string {
	// Generate id on first request. This is needed as id is not set when converting back from json
	if s.Id == "" {
		var fileID string
		switch s.FileIdentifier {
		case IdentifierPath:
			fileID = s.Source
		case IdentifierInodePath:
			fileID = s.FileStateOS.String() + ":" + s.Source
		case IdentifierInode:
			fileID = s.FileStateOS.String()
		default:
			// fileIdentifier is neither path nor inode_path, use inode default
			fileID = s.FileStateOS.String()
		}
		if len(s.Meta) == 0 {
			s.Id = fileID
		} else {
			hashValue, _ := hashstructure.Hash(s.Meta, nil)
			var hashBuf [17]byte
			hash := strconv.AppendUint(hashBuf[:0], hashValue, 16)
			hash = append(hash, '-')

			var b strings.Builder
			b.Grow(len(hash) + len(fileID))
			b.Write(hash)
			b.WriteString(fileID)

			s.Id = b.String()
		}
	}

	return s.Id
}

// IsEqual compares the state to an other state supporting stringer based on the unique string
func (s *State) IsEqual(c *State) bool {
	return s.ID() == c.ID()
}

// IsEmpty returns true if the state is empty
func (s *State) IsEmpty() bool {
	return s.FileStateOS == file.StateOS{} &&
		s.Source == "" &&
		len(s.Meta) == 0 &&
		s.Timestamp.IsZero()
}
