// +build !integration

package log

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sortedGlob(m *GreatestFileMatcher, pat string) ([]string, error) {
	got, err := m.Glob(pat)
	if err != nil {
		return nil, err
	}
	sort.Strings(got)
	return got, nil
}

func withLiteralFastPath(enabled bool, fn func()) {
	prev := enableLiteralFastPath
	enableLiteralFastPath = enabled
	defer func() { enableLiteralFastPath = prev }()
	fn()
}

func TestHasMeta(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"app.log", false},
		{"svc", false},
		{"*.log", true},
		{"app?.log", true},
		{"app[0-9].log", true},
		{"plain-name", false},
	}
	if runtime.GOOS != "windows" {
		cases = append(cases, struct {
			in   string
			want bool
		}{`foo\bar`, true}) // backslash is meta on non-Windows
	}
	for _, c := range cases {
		assert.Equal(t, c.want, hasMeta(c.in), "hasMeta(%q)", c.in)
	}
}

// TestLiteralFastPathEquivalence 关闭/开启字面快路径，对同一批 pattern 结果必须字节级一致。
// 覆盖：纯字面、末级通配、多级通配、缺失路径、大目录祖先、软链、挂载映射。
func TestLiteralFastPathEquivalence(t *testing.T) {
	base, err := os.MkdirTemp("", "literal-fastpath-eq-")
	require.NoError(t, err)
	defer os.RemoveAll(base)

	touch := func(p string) {
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		f, err := os.Create(p)
		require.NoError(t, err)
		require.NoError(t, f.Close())
	}

	touch(filepath.Join(base, "svc", "app", "logs", "app.log"))
	for i := 0; i < 200; i++ {
		touch(filepath.Join(base, "flat", "a"+strconv.Itoa(i)+".log"))
		touch(filepath.Join(base, "flat", "a"+strconv.Itoa(i)+".txt"))
	}
	for d := 0; d < 8; d++ {
		for i := 0; i < 6; i++ {
			ext := ".log"
			if i%2 == 1 {
				ext = ".txt"
			}
			touch(filepath.Join(base, "tree", "svc"+strconv.Itoa(d), "pod"+strconv.Itoa(d), "f"+strconv.Itoa(i)+ext))
		}
	}
	touch(filepath.Join(base, "realdir", "app", "f0.log"))
	touch(filepath.Join(base, "realdir", "app", "f1.log"))
	// 物理机 Fs==""：绝对软链，透明跟随
	require.NoError(t, os.Symlink(filepath.Join(base, "realdir"), filepath.Join(base, "linkdir")))
	// 容器 rootFs 场景：软链目标必须是「相对 rootFs 的绝对路径」，
	// 与既有 TestGreatestFileMatcher case 2.1.2 一致（Join(rootFs, linkTarget)）。
	require.NoError(t, os.Symlink("/realdir", filepath.Join(base, "linkdir_rooted")))
	for i := 0; i < 500; i++ {
		touch(filepath.Join(base, "big", "junk"+strconv.Itoa(i)+".dat"))
	}
	touch(filepath.Join(base, "big", "sub", "app.log"))
	touch(filepath.Join(base, "hostroot", "app", "m0.log"))
	touch(filepath.Join(base, "hostroot", "app", "m1.log"))

	patterns := []string{
		filepath.Join(base, "svc", "app", "logs", "app.log"),
		filepath.Join(base, "flat", "*.log"),
		filepath.Join(base, "tree", "svc*", "pod*", "*.log"),
		filepath.Join(base, "linkdir", "app", "*.log"),
		filepath.Join(base, "big", "sub", "app.log"),
		filepath.Join(base, "flat", "a1*.log"),
		filepath.Join(base, "nope", "missing.log"),
		filepath.Join(base, "flat", "a0.log"), // literal leaf in busy dir
	}

	matcher := NewGreatestFileMatcher("", nil)
	for _, pat := range patterns {
		var off, on []string
		withLiteralFastPath(false, func() {
			var err error
			off, err = sortedGlob(matcher, pat)
			require.NoError(t, err, "off pat=%s", pat)
		})
		withLiteralFastPath(true, func() {
			var err error
			on, err = sortedGlob(matcher, pat)
			require.NoError(t, err, "on pat=%s", pat)
		})
		assert.Equal(t, off, on, "literal fast path must not change matches for %s", pat)
	}

	// mount: container virtual path -> host dir
	mounts := []MountInfo{{
		ContainerPath: "/virtual",
		HostPath:      filepath.Join(base, "hostroot"),
	}}
	mMatcher := NewGreatestFileMatcher("", mounts)
	mPat := "/virtual/app/*.log"
	var offM, onM []string
	withLiteralFastPath(false, func() {
		var err error
		offM, err = sortedGlob(mMatcher, mPat)
		require.NoError(t, err)
	})
	withLiteralFastPath(true, func() {
		var err error
		onM, err = sortedGlob(mMatcher, mPat)
		require.NoError(t, err)
	})
	assert.Equal(t, offM, onM, "literal fast path must not change mount matches")
	assert.Len(t, onM, 2)

	// rootFs + symlink resolve (Fs != "")：pattern/软链目标均相对 rootFs
	rootMatcher := NewGreatestFileMatcher(base, nil)
	rPat := "/linkdir_rooted/app/*.log"
	var offR, onR []string
	withLiteralFastPath(false, func() {
		var err error
		offR, err = sortedGlob(rootMatcher, rPat)
		require.NoError(t, err)
	})
	withLiteralFastPath(true, func() {
		var err error
		onR, err = sortedGlob(rootMatcher, rPat)
		require.NoError(t, err)
	})
	assert.Equal(t, offR, onR, "literal fast path must not change rootFs symlink matches")
	assert.Len(t, onR, 2)
}

// TestLiteralFastPathKeepsPhysicalMatches 确保开启字面快路径后物理机场景匹配仍正确。
// 直接复用同套 fixture 的关键断言路径（物理机 Fs==""）。
func TestLiteralFastPathKeepsPhysicalMatches(t *testing.T) {
	base := "/tmp/literal-fastpath-phys"
	require.NoError(t, os.MkdirAll(filepath.Join(base, "sub"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(base, "a.txt"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(base, "b.txt"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(base, "sub", "c.txt"), []byte("x"), 0o644))
	defer os.RemoveAll(base)

	m := NewGreatestFileMatcher("", nil)
	withLiteralFastPath(true, func() {
		got, err := sortedGlob(m, filepath.Join(base, "*.txt"))
		require.NoError(t, err)
		assert.Equal(t, []string{
			filepath.Join(base, "a.txt"),
			filepath.Join(base, "b.txt"),
		}, got)

		got, err = sortedGlob(m, filepath.Join(base, "*", "*.txt"))
		require.NoError(t, err)
		assert.Equal(t, []string{filepath.Join(base, "sub", "c.txt")}, got)

		got, err = sortedGlob(m, filepath.Join(base, "a.txt"))
		require.NoError(t, err)
		assert.Equal(t, []string{filepath.Join(base, "a.txt")}, got)
	})
}
