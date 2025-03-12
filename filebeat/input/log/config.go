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
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dustin/go-humanize"

	cfg "github.com/elastic/beats/filebeat/config"
	"github.com/elastic/beats/filebeat/harvester"
	"github.com/elastic/beats/filebeat/input/file"
	"github.com/elastic/beats/libbeat/common/cfgwarn"
	"github.com/elastic/beats/libbeat/common/match"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/libbeat/reader/multiline"
	"github.com/elastic/beats/libbeat/reader/readjson"
)

var (
	defaultConfig = config{
		// Common
		ForwarderConfig: harvester.ForwarderConfig{
			Type: cfg.DefaultType,
		},
		CleanInactive: 0,

		// Input
		Enabled:        true,
		IgnoreOlder:    0,
		ScanFrequency:  10 * time.Second,
		CleanRemoved:   true,
		HarvesterLimit: 0,
		Symlinks:       false,
		TailFiles:      false,
		ScanSort:       "",
		ScanOrder:      "asc",
		RecursiveGlob:  true,

		// Harvester
		ReuseHarvester: true,
		ReuseMaxBytes:  100 * humanize.MiByte,

		BufferSize: 16 * humanize.KiByte,
		MaxBytes:   10 * humanize.MiByte,
		LogConfig: LogConfig{
			Backoff:       1 * time.Second,
			BackoffFactor: 2,
			MaxBackoff:    10 * time.Second,
			CloseInactive: 5 * time.Minute,
			CloseRemoved:  true,
			CloseRenamed:  false,
			CloseEOF:      false,
			CloseTimeout:  0,
		},
		LudicrousMode: false,
	}
)

// MountInfo 文件系统挂载信息
type MountInfo struct {
	HostPath      string `config:"hostpath"`
	ContainerPath string `config:"containerpath"`
}

// FilePath 带文件系统的文件路径
type FilePath struct {
	Fs   string
	Path string
	// Switched 是否已经切换过文件系统，最多只能切换一次
	Switched bool
}

type config struct {
	harvester.ForwarderConfig `config:",inline"`
	LogConfig                 `config:",inline"`

	// Common
	InputType     string        `config:"input_type"`
	CleanInactive time.Duration `config:"clean_inactive" validate:"min=0"`

	// Input
	Enabled        bool            `config:"enabled"`
	ExcludeFiles   []match.Matcher `config:"exclude_files"`
	IgnoreOlder    time.Duration   `config:"ignore_older"`
	Paths          []string        `config:"paths"`
	ScanFrequency  time.Duration   `config:"scan_frequency" validate:"min=0,nonzero"`
	CleanRemoved   bool            `config:"clean_removed"`
	HarvesterLimit uint32          `config:"harvester_limit" validate:"min=0"`
	Symlinks       bool            `config:"symlinks"`
	TailFiles      bool            `config:"tail_files"`
	RecursiveGlob  bool            `config:"recursive_glob.enabled"`

	// Harvester
	ReuseHarvester bool   `config:"reuse_harvester"`
	ReuseMaxBytes  int64  `config:"reuse_max_bytes"`
	BufferSize     int    `config:"harvester_buffer_size"`
	Encoding       string `config:"encoding"`
	ScanOrder      string `config:"scan.order"`
	ScanSort       string `config:"scan.sort"`

	ExcludeLines []match.Matcher   `config:"exclude_lines"`
	IncludeLines []match.Matcher   `config:"include_lines"`
	MaxBytes     int               `config:"max_bytes" validate:"min=0,nonzero"`
	Multiline    *multiline.Config `config:"multiline"`
	JSON         *readjson.Config  `config:"json"`

	// Hidden on purpose, used by the docker input:
	DockerJSON *struct {
		Stream   string `config:"stream"`
		Partial  bool   `config:"partial"`
		ForceCRI bool   `config:"force_cri_logs"`
		CRIFlags bool   `config:"cri_flags"`
	} `config:"docker-json"`

	// ludicrous mode, the collection speed of the single-line-log can reach 100+MB/s !!!
	LudicrousMode    bool        `config:"ludicrous_mode"`
	RemovePathPrefix string      `config:"remove_path_prefix"` // 去除路径前缀
	RootFS           string      `config:"root_fs"`            // 根目录文件系统
	Mounts           []MountInfo `config:"mounts"`             // 挂载路径信息
}

type LogConfig struct {
	Backoff       time.Duration `config:"backoff" validate:"min=0,nonzero"`
	BackoffFactor int           `config:"backoff_factor" validate:"min=1"`
	MaxBackoff    time.Duration `config:"max_backoff" validate:"min=0,nonzero"`
	CloseInactive time.Duration `config:"close_inactive"`
	CloseRemoved  bool          `config:"close_removed"`
	CloseRenamed  bool          `config:"close_renamed"`
	CloseEOF      bool          `config:"close_eof"`
	CloseTimeout  time.Duration `config:"close_timeout" validate:"min=0"`
}

// Contains available scan options
const (
	ScanOrderAsc     = "asc"
	ScanOrderDesc    = "desc"
	ScanSortNone     = ""
	ScanSortModtime  = "modtime"
	ScanSortFilename = "filename"
)

// ValidScanOrder of valid scan orders
var ValidScanOrder = map[string]struct{}{
	ScanOrderAsc:  {},
	ScanOrderDesc: {},
}

// ValidScanOrder of valid scan orders
var ValidScanSort = map[string]struct{}{
	ScanSortNone:     {},
	ScanSortModtime:  {},
	ScanSortFilename: {},
}

func (c *config) Validate() error {
	// DEPRECATED 6.0.0: warning is already outputted on input level
	if c.InputType != "" {
		c.Type = c.InputType
	}

	// Input
	if c.Type == harvester.LogType && len(c.Paths) == 0 {
		return fmt.Errorf("No paths were defined for input")
	}

	if c.CleanInactive != 0 && c.IgnoreOlder == 0 {
		return fmt.Errorf("ignore_older must be enabled when clean_inactive is used")
	}

	if c.CleanInactive != 0 && c.CleanInactive <= c.IgnoreOlder+c.ScanFrequency {
		return fmt.Errorf("clean_inactive must be > ignore_older + scan_frequency to make sure only files which are not monitored anymore are removed")
	}

	// Harvester
	if c.JSON != nil && len(c.JSON.MessageKey) == 0 &&
		c.Multiline != nil {
		return fmt.Errorf("When using the JSON decoder and multiline together, you need to specify a message_key value")
	}

	if c.JSON != nil && len(c.JSON.MessageKey) == 0 &&
		(len(c.IncludeLines) > 0 || len(c.ExcludeLines) > 0) {
		return fmt.Errorf("When using the JSON decoder and line filtering together, you need to specify a message_key value")
	}

	if c.ScanSort != "" {
		cfgwarn.Experimental("scan_sort is used.")

		// Check input type
		if _, ok := ValidScanSort[c.ScanSort]; !ok {
			return fmt.Errorf("Invalid scan sort: %v", c.ScanSort)
		}

		// Check input type
		if _, ok := ValidScanOrder[c.ScanOrder]; !ok {
			return fmt.Errorf("Invalid scan order: %v", c.ScanOrder)
		}
	}

	return nil
}

// resolveRecursiveGlobs expands `**` from the globs in multiple patterns
func (c *config) resolveRecursiveGlobs() error {
	if !c.RecursiveGlob {
		logp.Debug("input", "recursive glob disabled")
		return nil
	}

	logp.Debug("input", "recursive glob enabled")
	var paths []string
	for _, path := range c.Paths {
		patterns, err := file.GlobPatterns(path, recursiveGlobDepth)
		if err != nil {
			return err
		}
		if len(patterns) > 1 {
			logp.Debug("input", "%q expanded to %#v", path, patterns)
		}
		paths = append(paths, patterns...)
	}
	c.Paths = paths
	return nil
}

// normalizeGlobPatterns calls `filepath.Abs` on all the globs from config
func (c *config) normalizeGlobPatterns() error {
	var paths []string
	for _, path := range c.Paths {
		pathAbs, err := filepath.Abs(path)
		if err != nil {
			return fmt.Errorf("Failed to get the absolute path for %s: %v", path, err)
		}
		paths = append(paths, pathAbs)
	}
	c.Paths = paths
	return nil
}

func (c *config) IsLudicrousModeActivated() bool {
	inSingleLineScene := c.JSON == nil && c.Multiline == nil
	return c.LudicrousMode && inSingleLineScene
}

// GetFullPath 获取完整路径
func (f *FilePath) GetFullPath() string {
	return filepath.Join(f.Fs, f.Path)
}

// GreatestFileMatcher 地表最强支持多文件系统的文件匹配器
type GreatestFileMatcher struct {
	rootFs string
	mounts []MountInfo
}

// Glob 根据 pattern 匹配，并返回匹配的路径的列表
func (m *GreatestFileMatcher) Glob(pattern string) ([]string, error) {
	matches := make([]string, 0)
	err := m.GlobWithCallback(pattern, func(path string) error {
		matches = append(matches, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return matches, nil
}

// GlobWithCallback 根据 pattern 匹配，并将匹配的路径传给 callback 函数
func (m *GreatestFileMatcher) GlobWithCallback(pattern string, callback func(string) error) error {
	// 已经访问过的文件
	visited := map[string]struct{}{}
	// 对 pattern 进行目录层级拆解
	patterns := splitPath(pattern)

	volumeName := filepath.VolumeName(pattern) + string(filepath.Separator)

	return m.walk(patterns, 0, FilePath{Fs: m.rootFs, Path: volumeName}, visited, nil, callback)
}

// walk 遍历目录
func (m *GreatestFileMatcher) walk(patterns []string, depth int, currentPath FilePath, visited map[string]struct{}, fileInfo os.FileInfo, callback func(string) error) error {
	var err error

	// 切换到正确的文件系统
	switched := currentPath.Switched
	currentPath = m.selectFileSystem(currentPath)

	fullPath := currentPath.GetFullPath()

	// 避免重复访问
	if _, ok := visited[fullPath]; ok {
		return nil
	}
	// 记录访问过的文件
	visited[fullPath] = struct{}{}

	if switched != currentPath.Switched || fileInfo == nil {
		fileInfo, err = os.Lstat(fullPath)
		if err != nil {
			// 获取不到文件就拉倒
			logp.Debug("input", "[Glob func] File was not found: %s", fullPath)
			return nil
		}
	}

	// 匹配深度超过 pattern 数量，说明已经匹配完毕
	if depth >= len(patterns) {
		logp.Debug("input", "[Glob func] Depth is : %v, File is dir: %s", depth, fullPath)
		if !fileInfo.IsDir() {
			return callback(fullPath)
		}
		return nil
	}

	// 检查是否是符号链接
	if fileInfo.Mode()&os.ModeSymlink != 0 {
		// 获取链接指向的实际路径
		link, err := os.Readlink(fullPath)
		if err != nil {
			return err
		}
		// 如果是软链，替换为软链指向的路径
		if filepath.IsAbs(link) {
			currentPath.Path = link
		} else {
			currentPath.Path = filepath.Join(filepath.Dir(currentPath.Path), link)
		}
		// 平级再次遍历
		return m.walk(patterns, depth, currentPath, visited, nil, callback)
	}

	// 如果是目录，继续遍历
	if fileInfo.IsDir() {
		// 当前层级的匹配模式
		pattern := patterns[depth]

		// 遍历目录
		dirEntries, err := os.ReadDir(fullPath)
		if err != nil {
			return err
		}

		anyMatch := false
		for _, dirEntry := range dirEntries {
			// 匹配规则
			matched, err := filepath.Match(pattern, dirEntry.Name())
			if err != nil {
				return err
			}
			if !matched {
				continue
			}

			nextPath := FilePath{
				Fs:       currentPath.Fs,
				Path:     filepath.Join(currentPath.Path, dirEntry.Name()),
				Switched: currentPath.Switched,
			}

			nextFileInfo, _ := dirEntry.Info()
			// 遍历目录
			err = m.walk(patterns, depth+1, nextPath, visited, nextFileInfo, callback)
			if err != nil {
				return err
			}
			anyMatch = true
		}

		if !anyMatch {
			// 读不到也进去，死马当活马医，万一能跟挂载匹配上呢
			return m.walk(patterns, depth+1, FilePath{
				Fs:       currentPath.Fs,
				Path:     filepath.Join(currentPath.Path, pattern),
				Switched: currentPath.Switched,
			}, visited, nil, callback)
		}
		return nil
	}

	return err
}

// selectFileSystem 根据路径前缀自动配置文件系统
func (m *GreatestFileMatcher) selectFileSystem(dir FilePath) FilePath {
	if len(m.mounts) == 0 {
		return dir
	}

	if dir.Switched {
		// 已经切换过了，就无需处理
		return dir
	}

	// 先做路径标准化
	dirWithSuffix := appendSeparator(dir.Path)

	for _, mount := range m.mounts {
		if strings.HasPrefix(dirWithSuffix, mount.ContainerPath) {
			dir.Fs = mount.HostPath
			dir.Path = strings.Replace(dirWithSuffix, mount.ContainerPath, string(filepath.Separator), 1)
			dir.Switched = true
			return dir
		}
	}
	return dir
}

// splitPath 将路径分割为多个部分
func splitPath(path string) []string {
	// 1. 标准化路径（处理 ../, ./ 和多余分隔符）
	cleaned := filepath.Clean(path)

	// 2. 获取卷名（Windows 特性）
	volume := filepath.VolumeName(cleaned)
	remaining := cleaned[len(volume):]

	var parts []string

	// 3. 处理 UNC 路径（Windows 网络路径）
	if strings.HasPrefix(volume, `\\`) {
		// 分解 UNC 路径的服务器和共享名
		uncParts := strings.Split(strings.TrimPrefix(volume, `\\`), `\`)
		parts = append(parts, uncParts...)
	}

	// 4. 分割剩余路径部分
	splitFn := func(r rune) bool { return r == filepath.Separator }
	for _, p := range strings.FieldsFunc(remaining, splitFn) {
		if p != "" {
			parts = append(parts, p)
		}
	}

	return parts
}

// 给路径末尾补充分隔符
func appendSeparator(path string) string {
	if !strings.HasSuffix(path, string(filepath.Separator)) {
		return path + string(filepath.Separator)
	}
	return path
}

func NewGreatestFileMatcher(rootFs string, hostRoot string, mounts []MountInfo) *GreatestFileMatcher {
	// 根据 ContainerPath 文件路径的层级，从长到短对 Mounts 进行排序
	sort.Slice(mounts, func(i, j int) bool {
		return len(splitPath(mounts[i].ContainerPath)) > len(splitPath(mounts[j].ContainerPath))
	})
	// 补充分隔符 & 主机挂载根目录
	for idx, mount := range mounts {
		mounts[idx].ContainerPath = appendSeparator(mount.ContainerPath)
		mounts[idx].HostPath = appendSeparator(filepath.Join(hostRoot, mount.HostPath))
	}
	return &GreatestFileMatcher{
		rootFs: rootFs,
		mounts: mounts,
	}
}
