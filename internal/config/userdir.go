// The user config dir: seeding it from the example, filling in the git identity, and hashing what a create uses from it.

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/evsor/agent-sandbox/internal/hostfs"
)

// Paths in a config dir.
const (
	SpecFile      = "sandbox.toml"
	GitconfigFile = "image/etc/gitconfig"
)

// buildFiles are what docker build reads from a config dir: its .dockerignore lets only the Dockerfile and image/ in.
var buildFiles = []string{"Dockerfile", ".dockerignore", "image"}

// identityLine is the gitconfig line under [user] that the git name and email replace.
const identityLine = "# Add your name and email"

// Seeded is one example file and whether Seed wrote it.
type Seeded struct {
	Path string // slash-separated, relative to the config dir
	Made bool
}

// Seed writes each file of example that dir lacks, passed through fill, and never changes one dir has. It returns every example file
// in path order.
func Seed(dir string, example fs.FS, fill func(path string, data []byte) ([]byte, error)) ([]Seeded, error) {
	var seeded []Seeded

	err := fs.WalkDir(example, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		full := filepath.Join(dir, filepath.FromSlash(path))

		// Lstat: a link counts as an existing file, even a dangling one.
		_, err = os.Lstat(full)
		if err == nil {
			seeded = append(seeded, Seeded{Path: path})

			return nil
		}

		if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("checking %s: %w", full, err)
		}

		data, err := fs.ReadFile(example, path)
		if err != nil {
			return fmt.Errorf("reading the example %s: %w", path, err)
		}

		if data, err = fill(path, data); err != nil {
			return err
		}

		if err := hostfs.EnsureDir(filepath.Dir(full)); err != nil {
			return err
		}

		if err := writeNew(full, data); err != nil {
			return err
		}

		seeded = append(seeded, Seeded{Path: path, Made: true})

		return nil
	})

	return seeded, err
}

// writeNew creates the file with mode 0600, failing if anything exists at path.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // a path in the config dir, created only
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}

	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}

	if err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}

	return nil
}

// FillIdentity puts the git name and email that aren't empty in place of the identity line under [user] in gitconfig, leaving the
// rest as it is. With neither, gitconfig comes back unchanged.
func FillIdentity(gitconfig []byte, name, email string) ([]byte, error) {
	var identity []string

	for _, kv := range [][2]string{{"name", name}, {"email", email}} {
		// Each goes inside a quoted git config value.
		if strings.ContainsAny(kv[1], "\n\r\"\\") {
			return nil, fmt.Errorf("git %s %q: no newline, \" or \\", kv[0], kv[1])
		}

		if kv[1] != "" {
			identity = append(identity, fmt.Sprintf("\t%s = \"%s\"", kv[0], kv[1]))
		}
	}

	if len(identity) == 0 {
		return gitconfig, nil
	}

	lines := strings.Split(string(gitconfig), "\n")
	section := ""

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "[") {
			section = trimmed
		}

		if section == "[user]" && trimmed == identityLine {
			return []byte(strings.Join(slices.Replace(lines, i, i+1, identity...), "\n")), nil
		}
	}

	return nil, fmt.Errorf("the gitconfig has no %q line under [user]", identityLine)
}

// BuildHash returns the hex sha256 of the build context in fsys, a config dir.
func BuildHash(fsys fs.FS) (string, error) {
	return hash(fsys, buildFiles)
}

// DirHash returns the hex sha256 of what a create uses from fsys, a config dir: the build context and sandbox.toml.
func DirHash(fsys fs.FS) (string, error) {
	return hash(fsys, append(slices.Clone(buildFiles), SpecFile))
}

// hash covers the files at or under roots in path order, each as its path, length and contents. A root fsys lacks adds nothing.
func hash(fsys fs.FS, roots []string) (string, error) {
	var paths []string

	for _, root := range roots {
		err := fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
			if path == root && errors.Is(err, fs.ErrNotExist) {
				return nil
			}

			if err != nil || d.IsDir() {
				return err
			}

			paths = append(paths, path)

			return nil
		})
		if err != nil {
			return "", fmt.Errorf("listing %s: %w", root, err)
		}
	}

	slices.Sort(paths)

	h := sha256.New()

	for _, path := range paths {
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return "", fmt.Errorf("reading %s: %w", path, err)
		}

		fmt.Fprintf(h, "%s\x00%d\x00", path, len(data))
		h.Write(data)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
