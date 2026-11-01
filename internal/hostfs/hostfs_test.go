package hostfs

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sample is what the JSON tests write and read.
type sample struct {
	Name string `json:"name"`
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()

	info, err := os.Stat(path)
	require.NoError(t, err)

	return info.Mode().Perm()
}

func TestEnsureDir(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "a", "b")

	require.NoError(t, EnsureDir(dir))
	assert.Equal(t, os.FileMode(0o700), mode(t, dir))
	require.NoError(t, EnsureDir(dir), "an existing directory is fine")

	file := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(file, nil, 0o600))
	require.ErrorContains(t, EnsureDir(file), "creating")
}

func TestExists(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	require.NoError(t, os.WriteFile(file, nil, 0o600))

	tests := []struct {
		name    string
		path    string
		want    bool
		wantErr string
	}{
		{name: "a file", path: file, want: true},
		{name: "nothing there", path: filepath.Join(dir, "missing")},
		{name: "under a file", path: filepath.Join(file, "child"), wantErr: "checking"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Exists(tt.path)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestHomePath(t *testing.T) {
	t.Setenv("HOME", "/test-home")

	got, err := HomePath(".local", "bin")
	require.NoError(t, err)
	assert.Equal(t, "/test-home/.local/bin", got)

	t.Setenv("HOME", "")

	_, err = HomePath("x")
	require.ErrorContains(t, err, "finding the home directory")
}

func TestWriteIfChanged(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "file")

	changed, err := WriteIfChanged(path, []byte("one"))
	require.NoError(t, err)
	assert.True(t, changed, "a new file")
	assert.Equal(t, os.FileMode(0o600), mode(t, path))

	changed, err = WriteIfChanged(path, []byte("one"))
	require.NoError(t, err)
	assert.False(t, changed, "the same content")

	changed, err = WriteIfChanged(path, []byte("two"))
	require.NoError(t, err)
	assert.True(t, changed, "new content")

	got, err := os.ReadFile(path) //nolint:gosec // the test's own temporary directory
	require.NoError(t, err)
	assert.Equal(t, "two", string(got))

	_, err = WriteIfChanged(filepath.Join(path, "child"), nil)
	require.ErrorContains(t, err, "writing")
}

func TestJSON(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "file.json")

	got := sample{Name: "untouched"}
	require.NoError(t, ReadJSON(path, &got), "a missing file is fine")
	assert.Equal(t, "untouched", got.Name)

	changed, err := WriteJSON(path, sample{Name: "a"})
	require.NoError(t, err)
	assert.True(t, changed)

	raw, err := os.ReadFile(path) //nolint:gosec // the test's own temporary directory
	require.NoError(t, err)
	assert.JSONEq(t, `{"name": "a"}`, string(raw))
	assert.Contains(t, string(raw), "\n  \"name\": \"a\"\n}\n", "indented, with a final newline")

	changed, err = WriteJSON(path, sample{Name: "a"})
	require.NoError(t, err)
	assert.False(t, changed, "the same value")

	require.NoError(t, ReadJSON(path, &got))
	assert.Equal(t, "a", got.Name)
}

func TestJSON_errors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(bad, []byte("{"), 0o600))

	var got sample

	require.ErrorContains(t, ReadJSON(bad, &got), "parsing")
	require.ErrorContains(t, ReadJSON(dir, &got), "reading")

	_, err := WriteJSON(filepath.Join(dir, "out.json"), make(chan int))
	require.ErrorContains(t, err, "encoding")
}

func TestLock(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "lock")

	unlock, err := Lock(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), mode(t, path))

	other, err := os.Open(path) //nolint:gosec // the test's own temporary directory
	require.NoError(t, err)

	defer func() { _ = other.Close() }()

	tryLock := func() error { return syscall.Flock(int(other.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) }

	require.ErrorIs(t, tryLock(), syscall.EWOULDBLOCK, "held")

	unlock()

	require.NoError(t, tryLock(), "released")

	_, err = Lock(filepath.Join(path, "child"))
	require.ErrorContains(t, err, "opening the lock")
}

func TestCheckMode(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(path, nil, 0o600))

	require.NoError(t, CheckMode(path, 0o600))
	require.ErrorContains(t, CheckMode(path, 0o700), "is 600, want 700")
	require.ErrorContains(t, CheckMode(path+"-missing", 0o600), "reading the mode")
}
