package config

import (
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/evsor/agent-sandbox/example"
)

func readExample(t *testing.T, path string) []byte {
	t.Helper()

	raw, err := fs.ReadFile(example.FS, path)
	require.NoError(t, err)

	return raw
}

func TestFillSpec(t *testing.T) {
	t.Parallel()

	spec := readExample(t, "sandbox.toml")
	defaults := SpecValues{Name: "claude-sandbox", CPUs: "6", MemoryMiB: "12288"}

	tests := []struct {
		name    string
		example []byte
		values  SpecValues
		wantErr string
		changed []string // the lines that differ from the example, in order
	}{
		{name: "the defaults leave the example as it is", example: spec, values: defaults},
		{
			name:    "sets each value on its line",
			example: spec,
			values:  SpecValues{Name: "my-box", CPUs: "2", MemoryMiB: "4096"},
			changed: []string{`name = "my-box"`, "cpus = 2", "memory_mib = 4096"},
		},
		{
			name:    "writes numbers in their plain form",
			example: spec,
			values:  SpecValues{Name: "claude-sandbox", CPUs: "06", MemoryMiB: "12288"},
		},
		{name: "refuses an invalid name", example: spec, values: SpecValues{Name: "Bad_Name", CPUs: "6", MemoryMiB: "1"}, wantErr: `sandbox name "Bad_Name"`},
		{name: "refuses zero cpus", example: spec, values: SpecValues{Name: "sb", CPUs: "0", MemoryMiB: "1"}, wantErr: `cpus "0"`},
		{name: "refuses cpus past uint8", example: spec, values: SpecValues{Name: "sb", CPUs: "256", MemoryMiB: "1"}, wantErr: `cpus "256"`},
		{name: "refuses negative cpus", example: spec, values: SpecValues{Name: "sb", CPUs: "-1", MemoryMiB: "1"}, wantErr: `cpus "-1"`},
		{name: "refuses zero memory", example: spec, values: SpecValues{Name: "sb", CPUs: "1", MemoryMiB: "0"}, wantErr: `memory_mib "0"`},
		{name: "refuses memory past uint32", example: spec, values: SpecValues{Name: "sb", CPUs: "1", MemoryMiB: "4294967296"}, wantErr: `memory_mib "4294967296"`},
		{name: "refuses memory that isn't a number", example: spec, values: SpecValues{Name: "sb", CPUs: "1", MemoryMiB: "12G"}, wantErr: `memory_mib "12G"`},
		{
			name:    "refuses an example without the line",
			example: []byte("name = \"a\"\nimage = \"i\"\ncpus = 1\n"),
			values:  defaults,
			wantErr: "0 top-level memory_mib lines",
		},
		{
			name:    "ignores name keys in tables",
			example: []byte("image = \"i\"\ncpus = 1\nmemory_mib = 1\n[[volumes]]\nname = \"v\"\n"),
			values:  defaults,
			wantErr: "0 top-level name lines",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			filled, cfg, err := FillSpec(tt.example, tt.values)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.values.Name, cfg.Name)
			assert.Equal(t, tt.changed, changedLines(string(tt.example), string(filled)))
		})
	}
}

func TestFillGitconfig(t *testing.T) {
	t.Parallel()

	gitconfig := readExample(t, "image/etc/gitconfig")

	tests := []struct {
		name    string
		example []byte
		gitName string
		email   string
		wantErr string
		changed []string
	}{
		{name: "no identity leaves the example as it is", example: gitconfig},
		{
			name:    "puts both under user",
			example: gitconfig,
			gitName: "Your Name",
			email:   "1+you@users.noreply.github.com",
			changed: []string{"\tname = \"Your Name\"", "\temail = \"1+you@users.noreply.github.com\""},
		},
		{name: "leaves out an empty email", example: gitconfig, gitName: "Your Name", changed: []string{"\tname = \"Your Name\""}},
		{name: "keeps a comment character inside the quotes", example: gitconfig, gitName: "A #1; B", changed: []string{"\tname = \"A #1; B\""}},
		{name: "refuses a quote", example: gitconfig, gitName: `A "B"`, wantErr: "git name"},
		{name: "refuses a backslash", example: gitconfig, email: `a\b`, wantErr: "git email"},
		{name: "refuses a newline", example: gitconfig, gitName: "A\n[core]", wantErr: "git name"},
		{name: "refuses a carriage return", example: gitconfig, gitName: "A\rB", wantErr: "git name"},
		{name: "refuses an env reference", example: gitconfig, email: "${HOME}", wantErr: "git email"},
		{name: "refuses an example without the line", example: []byte("[user]\n\tuseConfigOnly = true\n"), gitName: "A", wantErr: "needs one line"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			filled, err := FillGitconfig(tt.example, tt.gitName, tt.email)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.changed, changedLines(string(tt.example), string(filled)))
		})
	}
}

// changedLines returns the lines of filled that aren't in example.
func changedLines(example, filled string) []string {
	old := strings.Split(example, "\n")

	var changed []string

	for line := range strings.SplitSeq(filled, "\n") {
		if !slices.Contains(old, line) {
			changed = append(changed, line)
		}
	}

	return changed
}
