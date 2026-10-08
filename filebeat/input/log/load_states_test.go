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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/beats/filebeat/harvester"
	"github.com/elastic/beats/filebeat/input/file"
	"github.com/elastic/beats/filebeat/util"
	libfile "github.com/elastic/beats/libbeat/common/file"
)

// collectOutlet records the states that loadStates pushes towards the registry.
type collectOutlet struct {
	states []file.State
	closed chan struct{}
}

func newCollectOutlet() *collectOutlet {
	return &collectOutlet{closed: make(chan struct{})}
}

func (o *collectOutlet) Close() error          { close(o.closed); return nil }
func (o *collectOutlet) Done() <-chan struct{} { return o.closed }
func (o *collectOutlet) OnEvent(d *util.Data) bool {
	o.states = append(o.states, d.GetState())
	return true
}

// linkedPaths writes content to oldName, hard links it to newName and then removes oldName.
// The result mirrors a container restart: the same physical file (same device + inode) is
// only reachable through a new path, because the old bind mount point is gone.
func linkedPaths(t *testing.T, content string) (oldPath, newPath string, info os.FileInfo) {
	t.Helper()

	dir := t.TempDir()
	oldPath = filepath.Join(dir, "old-pod-uid.log")
	newPath = filepath.Join(dir, "new-pod-uid.log")

	require.NoError(t, os.WriteFile(oldPath, []byte(content), 0o644))
	require.NoError(t, os.Link(oldPath, newPath))

	oldInfo, err := os.Stat(oldPath)
	require.NoError(t, err)
	newInfo, err := os.Stat(newPath)
	require.NoError(t, err)
	require.Equal(t,
		libfile.GetOSState(oldInfo).String(),
		libfile.GetOSState(newInfo).String(),
		"hard link must preserve device and inode, otherwise the test proves nothing",
	)

	require.NoError(t, os.Remove(oldPath))

	return oldPath, newPath, oldInfo
}

// registryState builds the state as it would be read back from the registry: Fileinfo and
// FileIdentifier are tagged json:"-" and are therefore absent after deserialization.
func registryState(source string, info os.FileInfo, offset int64, meta map[string]string) file.State {
	state := file.NewState(info, source, "log", meta, "")
	state.Finished = true
	state.Offset = offset
	state.Fileinfo = nil
	state.FileIdentifier = ""
	state.Id = ""
	return state
}

func newLoadStatesInput(t *testing.T, identifier, path string, meta map[string]string) (*Input, *collectOutlet) {
	t.Helper()

	outlet := newCollectOutlet()
	return &Input{
		config: config{
			ForwarderConfig: harvester.ForwarderConfig{Type: "log"},
			Paths:           []string{path},
			FileIdentifier:  identifier,
		},
		states: file.NewStates(),
		outlet: outlet,
		meta:   meta,
	}, outlet
}

// TestLoadStatesClaimsStateAcrossPathChange is the regression test for the container
// re-collection bug: with the default inode identifier the registry state has to be claimed
// through the new path, keeping the offset instead of restarting from 0.
func TestLoadStatesClaimsStateAcrossPathChange(t *testing.T) {
	const offset = int64(4096)

	oldPath, newPath, info := linkedPaths(t, "some already collected content")
	p, outlet := newLoadStatesInput(t, file.IdentifierInode, newPath, nil)

	require.NoError(t, p.loadStates([]file.State{registryState(oldPath, info, offset, nil)}))

	states := p.states.GetStates()
	require.Len(t, states, 1, "the state must be claimed through the new path")
	assert.Equal(t, offset, states[0].Offset, "offset must be inherited, not reset to 0")
	assert.Equal(t, newPath, states[0].Source, "Source must be refreshed, otherwise CleanRemoved drops the state")
	assert.Equal(t, file.IdentifierInode, states[0].FileIdentifier)
	assert.NotNil(t, states[0].Fileinfo, "Fileinfo must be refreshed, isCleanInactive reads ModTime")

	require.Len(t, outlet.states, 1, "the refreshed state must also be pushed to the registry")
	assert.Equal(t, newPath, outlet.states[0].Source)
}

// TestLoadStatesFindPreviousAfterPathChange covers the second half of the fix: the claimed
// state must be indexed under the same key that scan uses, so the harvester resumes from the
// stored offset instead of treating the file as new.
func TestLoadStatesFindPreviousAfterPathChange(t *testing.T) {
	const offset = int64(1234)

	oldPath, newPath, info := linkedPaths(t, "content")
	p, _ := newLoadStatesInput(t, file.IdentifierInode, newPath, nil)

	require.NoError(t, p.loadStates([]file.State{registryState(oldPath, info, offset, nil)}))

	newInfo, err := os.Stat(newPath)
	require.NoError(t, err)
	scanned := file.NewState(newInfo, newPath, "log", nil, file.IdentifierInode)

	previous := p.states.FindPrevious(scanned)
	require.False(t, previous.IsEmpty(), "scan must find the claimed state")
	assert.Equal(t, offset, previous.Offset, "harvester would otherwise start from 0")
}

// TestLoadStatesIdentifierScope pins down that the behaviour change is limited to the inode
// identifier. Under path and inode_path the key still contains the path, so a state stored
// under the old path must not be claimed - same as before the fix.
func TestLoadStatesIdentifierScope(t *testing.T) {
	tests := []struct {
		identifier string
		claimed    bool
	}{
		{identifier: file.IdentifierInode, claimed: true},
		{identifier: file.IdentifierPath, claimed: false},
		{identifier: file.IdentifierInodePath, claimed: false},
	}

	for _, test := range tests {
		t.Run(test.identifier, func(t *testing.T) {
			oldPath, newPath, info := linkedPaths(t, "content")
			p, _ := newLoadStatesInput(t, test.identifier, newPath, nil)

			require.NoError(t, p.loadStates([]file.State{registryState(oldPath, info, 512, nil)}))

			if test.claimed {
				assert.Equal(t, 1, p.states.Count())
			} else {
				assert.Equal(t, 0, p.states.Count())
			}
		})
	}
}

// TestLoadStatesSamePathStillClaimed guards the ordinary case - stable paths, as used by host
// collection - against a regression from the identifier change.
//
// The FindPrevious assertion additionally pins down a pre-existing bug: State.FileIdentifier is
// tagged json:"-", so a state loaded from the registry used to be indexed under the inode key
// regardless of configuration, while scan looks it up using the configured identifier. Under
// path and inode_path the two never matched and the file was harvested from 0 even though the
// path never changed.
func TestLoadStatesSamePathStillClaimed(t *testing.T) {
	for _, identifier := range []string{file.IdentifierInode, file.IdentifierPath, file.IdentifierInodePath} {
		t.Run(identifier, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "stable.log")
			require.NoError(t, os.WriteFile(path, []byte("content"), 0o644))

			info, err := os.Stat(path)
			require.NoError(t, err)

			p, _ := newLoadStatesInput(t, identifier, path, nil)
			require.NoError(t, p.loadStates([]file.State{registryState(path, info, 777, nil)}))

			states := p.states.GetStates()
			require.Len(t, states, 1)
			assert.Equal(t, int64(777), states[0].Offset)
			assert.Equal(t, path, states[0].Source)
			assert.Equal(t, identifier, states[0].FileIdentifier)

			previous := p.states.FindPrevious(file.NewState(info, path, "log", nil, identifier))
			require.False(t, previous.IsEmpty(), "scan must find the state under the configured identifier")
			assert.Equal(t, int64(777), previous.Offset)
		})
	}
}

// TestLoadStatesMetaMismatch keeps the existing meta semantics: a state belonging to another
// input must not be claimed even when the file identity matches.
func TestLoadStatesMetaMismatch(t *testing.T) {
	oldPath, newPath, info := linkedPaths(t, "content")

	p, _ := newLoadStatesInput(t, file.IdentifierInode, newPath, map[string]string{"id": "input-a"})
	state := registryState(oldPath, info, 512, map[string]string{"id": "input-b"})

	require.NoError(t, p.loadStates([]file.State{state}))
	assert.Equal(t, 0, p.states.Count(), "meta belongs to another input")

	p, _ = newLoadStatesInput(t, file.IdentifierInode, newPath, map[string]string{"id": "input-a"})
	state = registryState(oldPath, info, 512, map[string]string{"id": "input-a"})

	require.NoError(t, p.loadStates([]file.State{state}))
	assert.Equal(t, 1, p.states.Count(), "matching meta must still be claimed")
}

// TestLoadStatesClaimsStateOnce covers the bind mount case: two paths pointing at the same
// inode are both visible in one scan. The state must be claimed once, so the winner is
// deterministic instead of depending on glob order.
func TestLoadStatesClaimsStateOnce(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "a.log")
	second := filepath.Join(dir, "b.log")

	require.NoError(t, os.WriteFile(first, []byte("content"), 0o644))
	require.NoError(t, os.Link(first, second))

	info, err := os.Stat(first)
	require.NoError(t, err)

	p, outlet := newLoadStatesInput(t, file.IdentifierInode, filepath.Join(dir, "*.log"), nil)
	require.NoError(t, p.loadStates([]file.State{registryState(first, info, 256, nil)}))

	assert.Equal(t, 1, p.states.Count())
	assert.Len(t, outlet.states, 1, "the state must not be pushed twice")
}
