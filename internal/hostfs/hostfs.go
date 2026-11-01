// Package hostfs handles sbx's files on the host: files only their owner can read, directories only their owner can enter, and an
// exclusive file lock.
package hostfs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// EnsureDir creates a directory and its parents, with mode 0700, unless they exist.
func EnsureDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}

	return nil
}

// Exists reports whether path exists, following a link.
func Exists(path string) (bool, error) {
	_, err := os.Stat(path)

	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("checking %s: %w", path, err)
	}
}

// HomePath joins elem onto the user's home directory.
func HomePath(elem ...string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("finding the home directory: %w", err)
	}

	return filepath.Join(append([]string{home}, elem...)...), nil
}

// WriteIfChanged writes data with mode 0600 unless the file already holds it, and reports whether it wrote. A file that already exists
// keeps its mode.
func WriteIfChanged(path string, data []byte) (bool, error) {
	old, err := os.ReadFile(path) //nolint:gosec // a path sbx builds under its own state dir
	if err == nil && bytes.Equal(old, data) {
		return false, nil
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return false, fmt.Errorf("writing %s: %w", path, err)
	}

	return true, nil
}

// ReadJSON decodes the file at path into v. A missing file leaves v as it is.
func ReadJSON(path string, v any) error {
	data, err := os.ReadFile(path) //nolint:gosec // a path sbx builds under its own state dir
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	return nil
}

// WriteJSON writes v as indented JSON through WriteIfChanged, and reports whether it wrote.
func WriteJSON(path string, v any) (bool, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return false, fmt.Errorf("encoding %s: %w", path, err)
	}

	return WriteIfChanged(path, append(data, '\n'))
}

// Lock takes an exclusive lock on the file at path, creating it and waiting for any other holder. The function it returns releases it.
func Lock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // a path sbx builds under its own state dir
	if err != nil {
		return nil, fmt.Errorf("opening the lock: %w", err)
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()

		return nil, fmt.Errorf("taking the lock: %w", err)
	}

	return func() { _ = f.Close() }, nil // closing releases the flock
}

// CheckMode returns an error unless the permission bits of path are exactly want.
func CheckMode(path string, want fs.FileMode) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("reading the mode: %w", err)
	}

	if info.Mode().Perm() != want {
		return fmt.Errorf("%s is %o, want %o", path, info.Mode().Perm(), want)
	}

	return nil
}
