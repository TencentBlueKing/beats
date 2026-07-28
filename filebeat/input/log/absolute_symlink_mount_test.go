package log

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGreatestFileMatcherAbsoluteSymlinkAcrossMounts(t *testing.T) {
	baseDir := t.TempDir()
	rootFs := filepath.Join(baseDir, "rootfs")
	logMount := filepath.Join(baseDir, "log-mount")
	mntMount := filepath.Join(baseDir, "mnt-mount")
	targetDir := filepath.Join(mntMount, "lobby-17848742680-25swr")
	targetFile := filepath.Join(targetDir, "framework.log.1")

	require.NoError(t, os.MkdirAll(filepath.Join(rootFs, "data/home/user00"), 0o755))
	require.NoError(t, os.MkdirAll(logMount, 0o755))
	require.NoError(t, os.MkdirAll(targetDir, 0o755))
	require.NoError(t, os.WriteFile(targetFile, []byte("log"), 0o644))
	require.NoError(t, os.Symlink(
		"/data/home/user00/mnt/lobby-17848742680-25swr",
		filepath.Join(logMount, "lobby"),
	))

	matcher := NewGreatestFileMatcher(rootFs, []MountInfo{
		{
			HostPath:      logMount,
			ContainerPath: "/data/home/user00/log",
		},
		{
			HostPath:      mntMount,
			ContainerPath: "/data/home/user00/mnt",
		},
	})

	inputConfig := config{
		Paths:         []string{"/data/home/user00/log/**/framework.log.*"},
		RecursiveGlob: true,
	}
	require.NoError(t, inputConfig.resolveRecursiveGlobs())

	var matches []string
	for _, pattern := range inputConfig.Paths {
		patternMatches, err := matcher.Glob(pattern)
		require.NoError(t, err)
		matches = append(matches, patternMatches...)
	}
	assert.Equal(t, []string{targetFile}, matches)
}
