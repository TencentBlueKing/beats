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

package log

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/beats/filebeat/input/file"
)

func TestMarkStateForCleanupDefaultsToLegacyTTL(t *testing.T) {
	p := &Input{}
	state := file.State{TTL: -1, Finished: true}

	assert.Equal(t, time.Duration(0), p.markStateForCleanup(state, 0).TTL)
	assert.Equal(t, time.Duration(-2), p.markStateForCleanup(state, -2).TTL)
}

func TestMarkStateForCleanupSetsGraceOnce(t *testing.T) {
	const grace = 7 * 24 * time.Hour
	p := &Input{config: config{CleanRemovedGrace: grace}}
	state := file.State{TTL: -1, Finished: true}
	before := time.Now().Add(grace)

	marked := p.markStateForCleanup(state, 0)

	assert.Equal(t, time.Duration(-2), marked.TTL)
	if assert.NotNil(t, marked.GraceUntil) {
		assert.False(t, marked.GraceUntil.Before(before))
		assert.True(t, marked.GraceUntil.Before(time.Now().Add(grace+time.Second)))
	}

	firstDeadline := marked.GraceUntil
	marked = p.markStateForCleanup(marked, 0)
	assert.Equal(t, firstDeadline, marked.GraceUntil, "repeated scans must not extend the grace deadline")
}

func TestHarvestExistingFileCancelsGraceWhenUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "current.log")
	require.NoError(t, os.WriteFile(path, []byte("content"), 0o644))
	info, err := os.Stat(path)
	require.NoError(t, err)
	graceUntil := time.Now().Add(time.Hour)
	oldState := file.NewState(info, path, "log", nil, file.IdentifierInode)
	oldState.Finished = true
	oldState.Offset = info.Size()
	oldState.TTL = -2
	oldState.GraceUntil = &graceUntil

	outlet := newCollectOutlet()
	p := &Input{
		config: config{FileIdentifier: file.IdentifierInode},
		states: file.NewStates(),
		outlet: outlet,
	}
	p.states.SetStates([]file.State{oldState})
	newState := file.NewState(info, path, "log", nil, file.IdentifierInode)

	p.harvestExistingFile(newState, oldState)

	states := p.states.GetStates()
	if assert.Len(t, states, 1) {
		assert.Nil(t, states[0].GraceUntil)
		assert.Equal(t, time.Duration(-1), states[0].TTL)
		assert.Equal(t, oldState.Offset, states[0].Offset)
	}
}
