package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	example "github.com/evsor/agent-sandbox/config"
)

const (
	dockerfile   = "Dockerfile"
	dockerignore = ".dockerignore"
)

func exampleFS() fstest.MapFS {
	return fstest.MapFS{
		dockerfile:    {Data: []byte("FROM scratch\n")},
		dockerignore:  {Data: []byte("*\n")},
		GitconfigFile: {Data: []byte("[user]\n\t# Add your name and email\n")},
		SpecFile:      {Data: []byte("name = \"sb\"\n")},
	}
}

func readFile(t *testing.T, dir, path string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(path))) //nolint:gosec // the test's own temporary directory
	require.NoError(t, err)

	return string(data)
}

func keep(_ string, data []byte) ([]byte, error) { return data, nil }

func TestSeed(t *testing.T) {
	t.Parallel()

	all := []string{dockerignore, dockerfile, GitconfigFile, SpecFile}

	tests := []struct {
		name     string
		existing map[string]string // files in the dir before Seed, by slash path
		link     string            // a dangling link at this slash path before Seed
		fill     func(path string, data []byte) ([]byte, error)
		wantMade []string          // the files Seed writes, each filled first
		want     map[string]string // file contents afterwards, by slash path
		wantErr  string
	}{
		{
			name:     "an empty dir gets every file",
			fill:     keep,
			wantMade: all,
			want:     map[string]string{SpecFile: "name = \"sb\"\n", GitconfigFile: "[user]\n\t# Add your name and email\n"},
		},
		{
			name:     "an existing file is kept and not filled",
			existing: map[string]string{SpecFile: "name = \"mine\"\n", GitconfigFile: "[user]\n"},
			fill:     keep,
			wantMade: []string{dockerignore, dockerfile},
			want:     map[string]string{SpecFile: "name = \"mine\"\n", GitconfigFile: "[user]\n"},
		},
		{
			name:     "a dangling link counts as existing",
			link:     SpecFile,
			fill:     keep,
			wantMade: []string{dockerignore, dockerfile, GitconfigFile},
		},
		{
			name: "fill changes what is written",
			fill: func(path string, data []byte) ([]byte, error) {
				if path == GitconfigFile {
					return []byte("filled\n"), nil
				}

				return data, nil
			},
			wantMade: all,
			want:     map[string]string{GitconfigFile: "filled\n", dockerfile: "FROM scratch\n"},
		},
		{
			name:    "a fill error stops before that file",
			fill:    func(string, []byte) ([]byte, error) { return nil, errors.New("bad name") },
			wantErr: "bad name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			for path, body := range tt.existing {
				full := filepath.Join(dir, filepath.FromSlash(path))
				require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o700))
				require.NoError(t, os.WriteFile(full, []byte(body), 0o600))
			}

			if tt.link != "" {
				require.NoError(t, os.Symlink(filepath.Join(dir, "target"), filepath.Join(dir, tt.link)))
			}

			var filled []string

			got, err := Seed(dir, exampleFS(), func(path string, data []byte) ([]byte, error) {
				filled = append(filled, path)

				return tt.fill(path, data)
			})

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				assert.NoFileExists(t, filepath.Join(dir, dockerignore), "nothing is written for a file whose fill fails")

				return
			}

			require.NoError(t, err)

			var made, paths []string

			for _, f := range got {
				paths = append(paths, f.Path)

				if f.Made {
					made = append(made, f.Path)
				}
			}

			assert.Equal(t, all, paths, "every example file, in path order")
			assert.Equal(t, tt.wantMade, made)
			assert.Equal(t, tt.wantMade, filled, "only written files are filled")

			for _, path := range made {
				info, err := os.Stat(filepath.Join(dir, filepath.FromSlash(path)))
				require.NoError(t, err)
				assert.Equal(t, fs.FileMode(0o600), info.Mode().Perm(), path)
			}

			for path, body := range tt.want {
				assert.Equal(t, body, readFile(t, dir, path), path)
			}

			assert.NoFileExists(t, filepath.Join(dir, "target"), "nothing is written through a link")
		})
	}
}

func TestFillIdentity(t *testing.T) {
	t.Parallel()

	const refused = "no newline"

	const gitconfig = "[core]\n\t# Add your name and email\n[user]\n\t# Add your name and email\n\tuseConfigOnly = true\n"

	tests := []struct {
		name      string
		gitconfig string
		gitName   string
		gitEmail  string
		want      string
		wantErr   string
	}{
		{
			name:    "both replace the line under [user] only",
			gitName: "Jane Doe", gitEmail: "1+jane@users.noreply.github.com",
			want: "[core]\n\t# Add your name and email\n[user]\n\tname = \"Jane Doe\"\n\temail = \"1+jane@users.noreply.github.com\"\n" +
				"\tuseConfigOnly = true\n",
		},
		{
			name:    "a name alone",
			gitName: "Jane",
			want:    "[core]\n\t# Add your name and email\n[user]\n\tname = \"Jane\"\n\tuseConfigOnly = true\n",
		},
		{
			name: "neither leaves the file as it is",
			want: gitconfig,
		},
		{name: "a newline is refused", gitName: "Jane\n[core]", wantErr: refused},
		{name: "a carriage return is refused", gitEmail: "j@x\r", wantErr: refused},
		{name: "a quote is refused", gitName: `Jane "JD" Doe`, wantErr: refused},
		{name: "a backslash is refused", gitName: `Jane\Doe`, wantErr: refused},
		{
			name:      "no identity line under [user]",
			gitconfig: "[core]\n\t# Add your name and email\n[user]\n\tuseConfigOnly = true\n",
			gitName:   "Jane",
			wantErr:   "no \"# Add your name and email\" line under [user]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			in := tt.gitconfig
			if in == "" {
				in = gitconfig
			}

			got, err := FillIdentity([]byte(in), tt.gitName, tt.gitEmail)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestFillIdentity_example(t *testing.T) {
	t.Parallel()

	raw, err := fs.ReadFile(example.FS, GitconfigFile)
	require.NoError(t, err)

	got, err := FillIdentity(raw, "Jane", "j@example.com")
	require.NoError(t, err)
	assert.Contains(t, string(got), "[user]\n\tname = \"Jane\"\n\temail = \"j@example.com\"\n\tuseConfigOnly = true\n")
}

func TestBuildHash(t *testing.T) {
	t.Parallel()

	base, err := BuildHash(exampleFS())
	require.NoError(t, err)

	tests := []struct {
		name   string
		change func(fstest.MapFS)
		same   bool
	}{
		{name: "an image file's contents", change: func(m fstest.MapFS) { m[GitconfigFile] = &fstest.MapFile{Data: []byte("x")} }},
		{name: "a new image file", change: func(m fstest.MapFS) { m["image/etc/new"] = &fstest.MapFile{Data: []byte("x")} }},
		{name: "the Dockerfile", change: func(m fstest.MapFS) { m[dockerfile] = &fstest.MapFile{Data: []byte("FROM x\n")} }},
		{name: "the .dockerignore", change: func(m fstest.MapFS) { delete(m, dockerignore) }},
		{
			name: "a rename with the same contents",
			change: func(m fstest.MapFS) {
				m["image/etc/gitconfig2"] = m[GitconfigFile]
				delete(m, GitconfigFile)
			},
		},
		{name: "sandbox.toml is not built", change: func(m fstest.MapFS) { m[SpecFile] = &fstest.MapFile{Data: []byte("x")} }, same: true},
		{name: "other files are not built", change: func(m fstest.MapFS) { m["notes.txt"] = &fstest.MapFile{Data: []byte("x")} }, same: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := exampleFS()
			tt.change(m)

			got, err := BuildHash(m)
			require.NoError(t, err)
			assert.Len(t, got, 64)

			if tt.same {
				assert.Equal(t, base, got)
			} else {
				assert.NotEqual(t, base, got)
			}
		})
	}
}

func TestDirHash(t *testing.T) {
	t.Parallel()

	base, err := DirHash(exampleFS())
	require.NoError(t, err)

	tests := []struct {
		name   string
		change func(fstest.MapFS)
		same   bool
	}{
		{name: "nothing", change: func(fstest.MapFS) {}, same: true},
		{name: "sandbox.toml", change: func(m fstest.MapFS) { m[SpecFile] = &fstest.MapFile{Data: []byte("x")} }},
		{name: "an image file", change: func(m fstest.MapFS) { m[GitconfigFile] = &fstest.MapFile{Data: []byte("x")} }},
		{name: "other files are not used", change: func(m fstest.MapFS) { m["sandbox.toml~"] = &fstest.MapFile{Data: []byte("x")} }, same: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := exampleFS()
			tt.change(m)

			got, err := DirHash(m)
			require.NoError(t, err)

			if tt.same {
				assert.Equal(t, base, got)
			} else {
				assert.NotEqual(t, base, got)
			}
		})
	}
}
