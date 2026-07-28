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
	runtimeMount := filepath.Join(baseDir, "runtime-mount")
	targetDir := filepath.Join(runtimeMount, "instance-a")
	targetFile := filepath.Join(targetDir, "service.log.1")

	require.NoError(t, os.MkdirAll(filepath.Join(rootFs, "workload"), 0o755))
	require.NoError(t, os.MkdirAll(logMount, 0o755))
	require.NoError(t, os.MkdirAll(targetDir, 0o755))
	require.NoError(t, os.WriteFile(targetFile, []byte("log"), 0o644))
	require.NoError(t, os.Symlink(
		"/workload/runtime/instance-a",
		filepath.Join(logMount, "current"),
	))

	matcher := NewGreatestFileMatcher(rootFs, []MountInfo{
		{
			HostPath:      logMount,
			ContainerPath: "/workload/logs",
		},
		{
			HostPath:      runtimeMount,
			ContainerPath: "/workload/runtime",
		},
	})

	inputConfig := config{
		Paths:         []string{"/workload/logs/**/service.log.*"},
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
