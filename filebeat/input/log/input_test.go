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

package log

import (
	"github.com/bmatcuk/doublestar/v4"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/beats/filebeat/input/file"
	"github.com/elastic/beats/libbeat/common/match"
)

func TestInputFileExclude(t *testing.T) {
	p := Input{
		config: config{
			ExcludeFiles: []match.Matcher{match.MustCompile(`\.gz$`)},
		},
	}

	assert.True(t, p.isFileExcluded("/tmp/log/logw.gz"))
	assert.False(t, p.isFileExcluded("/tmp/log/logw.log"))
}

func TestGlobWithSymlinks(t *testing.T) {
	/*
		创建文件夹 /tmp
		目录结构示例
		/tmp
		├── data/
		│   ├── app.log
		│   ├── subdir/
		│   │   └── api.log
		│   └── link_logs -> /external/logs  //容器内软链接，链接到相对目录
		└── external/
			└── logs/
				├── system.log
				└── old/
					└── system.log
	*/

	tmpDir := t.TempDir()

	// 主数据目录结构
	dataDir := filepath.Join(tmpDir, "data")
	os.MkdirAll(dataDir, 0755)
	os.WriteFile(filepath.Join(dataDir, "app.log"), []byte("test"), 0644)
	os.Mkdir(filepath.Join(dataDir, "subdir"), 0755)
	os.WriteFile(filepath.Join(dataDir, "subdir", "api.log"), []byte("test"), 0644)

	// 外部日志目录（软链目标）
	externalLogsDir := filepath.Join(tmpDir, "external", "logs")
	os.MkdirAll(externalLogsDir, 0755)
	os.WriteFile(filepath.Join(externalLogsDir, "system.log"), []byte("test"), 0644)
	os.Mkdir(filepath.Join(externalLogsDir, "old"), 0755)
	os.WriteFile(filepath.Join(externalLogsDir, "old", "system.log"), []byte("test"), 0644)

	// 创建软链：data/link_logs -> external/logs
	os.Symlink(filepath.Join(tmpDir, "external", "logs"), filepath.Join(dataDir, "link_logs"))

	// 构建模式
	pattern := filepath.Join("data", "**", "*.log")
	matches, err := doublestar.Glob(os.DirFS(tmpDir), pattern, doublestar.WithFilesOnly())
	if err != nil {
		t.Fatalf("Glob failed: %v", err)
	}

	expected := []string{
		filepath.Join(dataDir, "app.log"),
		filepath.Join(dataDir, "subdir", "api.log"),
		filepath.Join(tmpDir, "external", "logs", "system.log"),        // 软链直接文件
		filepath.Join(tmpDir, "external", "logs", "old", "system.log"), // 软链子目录文件
	}

	if len(matches) != len(expected) {
		t.Fatalf("Expected %d matches, got %d", len(expected), len(matches))
	}

	for _, exp := range expected {
		found := false
		for _, m := range matches {
			if filepath.Join(tmpDir, m) == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected match not found: %s", exp)
		}
	}
}

var cleanInactiveTests = []struct {
	cleanInactive time.Duration
	fileTime      time.Time
	result        bool
}{
	{
		cleanInactive: 0,
		fileTime:      time.Now(),
		result:        false,
	},
	{
		cleanInactive: 1 * time.Second,
		fileTime:      time.Now().Add(-5 * time.Second),
		result:        true,
	},
	{
		cleanInactive: 10 * time.Second,
		fileTime:      time.Now().Add(-5 * time.Second),
		result:        false,
	},
}

func TestIsCleanInactive(t *testing.T) {
	for _, test := range cleanInactiveTests {

		l := Input{
			config: config{
				CleanInactive: test.cleanInactive,
			},
		}
		state := file.State{
			Fileinfo: TestFileInfo{
				time: test.fileTime,
			},
		}

		assert.Equal(t, test.result, l.isCleanInactive(state))
	}
}

func TestMatchesMeta(t *testing.T) {
	tests := []struct {
		Input  *Input
		Meta   map[string]string
		Result bool
	}{
		{
			Input: &Input{
				meta: map[string]string{
					"it": "matches",
				},
			},
			Meta: map[string]string{
				"it": "matches",
			},
			Result: true,
		},
		{
			Input: &Input{
				meta: map[string]string{
					"it":     "doesnt",
					"doesnt": "match",
				},
			},
			Meta: map[string]string{
				"it": "doesnt",
			},
			Result: false,
		},
		{
			Input: &Input{
				meta: map[string]string{
					"it": "doesnt",
				},
			},
			Meta: map[string]string{
				"it":     "doesnt",
				"doesnt": "match",
			},
			Result: false,
		},
		{
			Input: &Input{
				meta: map[string]string{},
			},
			Meta:   map[string]string{},
			Result: true,
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.Result, test.Input.matchesMeta(test.Meta))
	}
}

type TestFileInfo struct {
	time time.Time
}

func (t TestFileInfo) Name() string       { return "" }
func (t TestFileInfo) Size() int64        { return 0 }
func (t TestFileInfo) Mode() os.FileMode  { return 0 }
func (t TestFileInfo) ModTime() time.Time { return t.time }
func (t TestFileInfo) IsDir() bool        { return false }
func (t TestFileInfo) Sys() interface{}   { return nil }
