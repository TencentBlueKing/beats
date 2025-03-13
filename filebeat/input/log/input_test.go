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
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"testing"
	"time"

	"github.com/elastic/beats/filebeat/input/file"
	"github.com/elastic/beats/libbeat/common/match"
	"github.com/stretchr/testify/assert"
)

const (
	totalFiles   = 100000 // 十万个文件
	maxDepth     = 2      // 最大目录层级
	baseDir      = "/tmp/logs"
	matchPattern = "/tmp/logs/*/*/*.log"
)

// 生成随机目录结构
func generateRandomPath(r *rand.Rand, depth int) string {
	if depth > maxDepth {
		return ""
	}

	path := baseDir
	for i := 0; i < 2; i++ { // 确保至少两层目录
		dir := fmt.Sprintf("dir%d", r.Intn(1000))
		path = filepath.Join(path, dir)
		if depth == maxDepth-1 {
			break
		}
		depth++
	}
	return path
}

// 初始化测试环境
func setup() {
	os.RemoveAll(baseDir)
	os.MkdirAll(baseDir, 0755)

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	sem := make(chan struct{}, 100) // 并发控制

	for i := 0; i < totalFiles; i++ {
		sem <- struct{}{}
		go func(i int) {
			defer func() { <-sem }()
			path := generateRandomPath(r, 0)
			os.MkdirAll(path, 0755)
			fpath := filepath.Join(path, fmt.Sprintf("file%d.log", i))
			ioutil.WriteFile(fpath, []byte{}, 0644)
		}(i)
	}

	// 等待所有goroutine完成
	for i := 0; i < cap(sem); i++ {
		sem <- struct{}{}
	}
}

// 清理测试环境
func teardown() {
	os.RemoveAll(baseDir)
}

// Benchmark测试
func BenchmarkFPGlobPerformance(b *testing.B) {
	//setup()
	//defer teardown()

	// 生成 CPU Profile
	f, _ := os.Create("cpu_fp.pprof")
	pprof.StartCPUProfile(f)
	defer pprof.StopCPUProfile()

	// 生成 Memory Profile
	mf, _ := os.Create("mem_fp.pprof")
	defer pprof.WriteHeapProfile(mf)

	b.ResetTimer() // 重置计时器，排除准备时间
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// 执行模式匹配

		matches, err := filepath.Glob(matchPattern)
		if err != nil {
			b.Fatalf("FilePath Glob failed: %v", err)
		}

		// 验证匹配数量
		if len(matches) != totalFiles {
			b.Errorf("Expected %d matches, got %d", totalFiles, len(matches))
		}

		// 内存统计
		b.StopTimer()
		var mstat runtime.MemStats
		runtime.ReadMemStats(&mstat)
		b.Logf("HeapAlloc: %.2f MB", float64(mstat.HeapAlloc)/1024/1024)
		b.StartTimer()
	}
}

// Benchmark测试
func BenchmarkGlobPerformance(b *testing.B) {
	//setup()
	//defer teardown()

	// 生成 CPU Profile
	f, _ := os.Create("cpu_new.pprof")
	pprof.StartCPUProfile(f)
	defer pprof.StopCPUProfile()

	// 生成 Memory Profile
	mf, _ := os.Create("mem_new.pprof")
	defer pprof.WriteHeapProfile(mf)

	b.ResetTimer() // 重置计时器，排除准备时间
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// 执行模式匹配
		matcher := NewGreatestFileMatcher("", nil)

		matches, err := matcher.Glob(matchPattern)
		if err != nil {
			b.Fatalf("NewGreatestFileMatcher Glob failed: %v", err)
		}

		// 验证匹配数量
		if len(matches) != totalFiles {
			b.Errorf("Expected %d matches, got %d", totalFiles, len(matches))
		}

		// 内存统计
		b.StopTimer()
		var mstat runtime.MemStats
		runtime.ReadMemStats(&mstat)
		b.Logf("HeapAlloc: %.2f MB", float64(mstat.HeapAlloc)/1024/1024)
		b.StartTimer()
	}
}

// 单元测试验证文件生成
func TestFileGeneration(t *testing.T) {
	setup()
	defer teardown()

	// 验证文件数量
	var count int
	filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() && filepath.Ext(path) == ".log" {
			count++
		}
		return nil
	})

	if count != totalFiles {
		t.Errorf("Expected %d files, got %d", totalFiles, count)
	}
}

func TestGreatestFileMatcher(t *testing.T) {
	/*
			  创建文件夹 /tmp/test
			  目录结构示例
			  /tmp/test
			  ├── file1.txt
			  ├── file2.txt
			  ├── subdir
			  │   └── file3.txt
			  ├── link_dir -> /cccc/
		      /tmp/test2
			  └── host_space
				  └── file4.txt
	*/
	if err := os.MkdirAll("/tmp", 0755); err != nil {
		panic(err)
	}
	if err := os.MkdirAll("/tmp/test", 0755); err != nil {
		panic(err)
	}
	// 创建文件 /tmp/test/file1.txt
	if err := os.WriteFile("/tmp/test/file1.txt", []byte("Hello, World!"), 0644); err != nil {
		panic(err)
	}
	// 创建文件 /tmp/test/file2.txt
	if err := os.WriteFile("/tmp/test/file2.txt", []byte("Hello, World!"), 0644); err != nil {
		panic(err)
	}
	// 创建文件夹 /tmp/test/subdir
	if err := os.MkdirAll("/tmp/test/sub_dir", 0755); err != nil {
		panic(err)
	}
	// 创建文件 /tmp/test/subdir/file3.txt
	if err := os.WriteFile("/tmp/test/sub_dir/file3.txt", []byte("Hello, World!"), 0644); err != nil {
		panic(err)
	}
	// 创建文件夹 /tmp/test/host_space
	if err := os.MkdirAll("/tmp/test2/host_space", 0755); err != nil {
		panic(err)
	}
	// 创建文件 /tmp/test/host_space/file4.log
	if err := os.WriteFile("/tmp/test2/host_space/file4.txt", []byte("Hello, World!"), 0644); err != nil {
		panic(err)
	}
	// 创建符号链接 /tmp/test/link_dir/ -> /cccc/  如果有就不创建
	if _, err := os.Lstat("/tmp/test/link_dir"); err != nil {
		if err := os.Symlink("/cccc/", "/tmp/test/link_dir"); err != nil {
			panic(err)
		}
	}

	// case 1.1: 基本测试
	matcher := NewGreatestFileMatcher("", nil)

	matches, err := matcher.Glob("/tmp/test/*.txt")
	if err != nil {
		panic(err)
	}
	assert.Equal(t, []string{"/private/tmp/test/file1.txt", "/private/tmp/test/file2.txt"}, matches)

	// case 1.2: 基本测试
	matches, err = matcher.Glob("/tmp/test/*/*.txt")
	if err != nil {
		panic(err)
	}
	assert.Equal(t, []string{"/private/tmp/test/sub_dir/file3.txt"}, matches)

	// case 1.3: 基本测试
	matches, err = matcher.Glob("/xxx/test/*/*.log")
	if err != nil {
		panic(err)
	}
	assert.Equal(t, []string{}, matches)

	// case 2.1.1: 基本软链测试
	matches, err = matcher.Glob("/tmp/test/link_dir/*.txt")
	if err != nil {
		panic(err)
	}
	assert.Equal(t, []string{}, matches)

	// case 2.1.2: 指定根目录软链测试
	matcher = NewGreatestFileMatcher("/tmp/test", nil)
	matches, err = matcher.Glob("/link_dir/*.txt")

	// case 2.2: 见证奇迹的时候
	matcher = NewGreatestFileMatcher("", []MountInfo{
		{
			HostPath:      "/tmp/test2/host_space",
			ContainerPath: "/cccc",
		},
	})
	matches, err = matcher.Glob("/tmp/test/link_dir/*.txt")
	if err != nil {
		panic(err)
	}
	assert.Equal(t, []string{"/tmp/test2/host_space/file4.txt"}, matches)

	// case 2.3: ...
	matcher = NewGreatestFileMatcher("", []MountInfo{
		{
			HostPath:      "/tmp/test2/host_space",
			ContainerPath: "/cccc",
		},
	})
	matches, err = matcher.Glob("/tmp/test/*/file4.txt")
	if err != nil {
		panic(err)
	}
	assert.Equal(t, []string{"/tmp/test2/host_space/file4.txt"}, matches)

	// case 2.4 ...
	matcher = NewGreatestFileMatcher("/tmp/test", []MountInfo{
		{
			HostPath:      "/tmp/test2/host_space",
			ContainerPath: "/cccc",
		},
	})
	matches, err = matcher.Glob("/cccc/*.txt")
	if err != nil {
		panic(err)
	}
	assert.Equal(t, []string{"/tmp/test2/host_space/file4.txt"}, matches)

	// case 2.5 主机挂载根目录转换
	matcher = NewGreatestFileMatcher("/tmp/test", []MountInfo{
		{
			HostPath:      "/tmp/test2/host_space",
			ContainerPath: "/cccc",
		},
	})
	matches, err = matcher.Glob("/*/*")
	if err != nil {
		panic(err)
	}
	assert.Equal(t, []string{"/tmp/test2/host_space/file4.txt"}, matches)

	// case 2.6 文件不存在边界情况
	matcher = NewGreatestFileMatcher("/tmp/test", []MountInfo{
		{
			HostPath:      "/tmp/test2/host_space",
			ContainerPath: "/cccc",
		},
	})
	matches, err = matcher.Glob("/*/no_exist.txt")
	if err != nil {
		panic(err)
	}
	fmt.Printf("excepted: %v => actual: %v\n", []string{}, matches)

}

func TestInputFileExclude(t *testing.T) {
	p := Input{
		config: config{
			ExcludeFiles: []match.Matcher{match.MustCompile(`\.gz$`)},
		},
	}

	assert.True(t, p.isFileExcluded("/tmp/log/logw.gz"))
	assert.False(t, p.isFileExcluded("/tmp/log/logw.log"))
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
