package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeSpec(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "sandbox.toml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	return path
}

func TestLoad(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		body    string
		wantErr string
		check   func(t *testing.T, cfg *Config)
	}{
		{
			name: "maps every key",
			body: `
name = "sb"
image = "img"
cpus = 2
memory_mib = 1024
root_disk_mib = 2048
user = "node"
workdir = "/w"
shell = "/bin/bash"
security = "restricted"
env = ["GH_TOKEN=ph=x"]
[[volumes]]
name = "v"
target = "/w"
kind = "disk"
size_mib = 10
nosuid = true
nodev = true
[network]
default_egress = "deny"
default_ingress = "deny"
strict = true
intercept_tls = true
[[network.rules]]
action = "allow"
direction = "egress"
destination = "example.com"
protocol = "tcp"
port = "443"
[[secrets]]
name = "GITHUB_PAT"
allow = ["github.com"]
placeholder = "PH"
header_fields = ["authorization"]
violation_action = "block-and-log"
`,
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				assert.Equal(t, "sb", cfg.Name)
				assert.Equal(t, uint8(2), cfg.CPUs)
				assert.Equal(t, uint32(1024), cfg.MemoryMiB)
				assert.Equal(t, uint32(2048), cfg.RootDiskMiB)
				assert.Equal(t, Volume{Name: "v", Target: "/w", Kind: "disk", SizeMiB: 10, Nosuid: true, Nodev: true}, cfg.Volumes[0])
				assert.Equal(t, Rule{Action: "allow", Direction: "egress", Destination: "example.com", Protocol: "tcp", Port: "443"}, cfg.Network.Rules[0])
				assert.True(t, cfg.Network.Strict)
				assert.True(t, cfg.Network.InterceptTLS)
				assert.Equal(t, "GITHUB_PAT", cfg.Secrets[0].Name, "secret names keep their case")
				assert.Equal(t, []string{"authorization"}, cfg.Secrets[0].HeaderFields)
			},
		},
		{name: "rejects an unknown key", body: "name = \"sb\"\nimage = \"i\"\nports = [\"80:80\"]\n", wantErr: "ports"},
		{name: "requires an image", body: "name = \"sb\"\n", wantErr: "image is required"},
		{name: "requires a name", body: "image = \"i\"\n", wantErr: "want lowercase"},
		{name: "rejects a name that could inject ssh config", body: "name = \"sb\\nProxyCommand x\"\nimage = \"i\"\n", wantErr: "want lowercase"},
		{name: "rejects an env entry without =", body: "name = \"sb\"\nimage = \"i\"\nenv = [\"NOVALUE\"]\n", wantErr: "want NAME=value"},
		{name: "rejects invalid TOML", body: "name = ", wantErr: "reading"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg, err := Load(writeSpec(t, tt.body))
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			tt.check(t, cfg)
		})
	}
}

func TestLoad_repoFile(t *testing.T) {
	t.Parallel()

	cfg, err := Load(filepath.Join("..", "..", "config", "sandbox.toml"))
	require.NoError(t, err)

	assert.Equal(t, "claude-sandbox", cfg.Name)
	assert.Equal(t, uint32(16384), cfg.RootDiskMiB)
	assert.Len(t, cfg.Volumes, 2)
	assert.Empty(t, cfg.Secrets)
}

func TestConfig_EnvMap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		env     []string
		want    map[string]string
		wantErr bool
	}{
		{name: "empty", env: nil, want: map[string]string{}},
		{name: "splits at the first =", env: []string{"A=b=c", "D="}, want: map[string]string{"A": "b=c", "D": ""}},
		{name: "rejects an empty name", env: []string{"=x"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := (&Config{Env: tt.env}).EnvMap()
			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConfig_SecretNames(t *testing.T) {
	t.Parallel()

	cfg := &Config{Secrets: []Secret{{Name: "A"}, {Name: "B"}}}
	assert.Equal(t, []string{"A", "B"}, cfg.SecretNames())
}

func TestSecretValues(t *testing.T) {
	t.Parallel()

	env := map[string]string{"SET": "DUMMY-SECRET-123", "ALSO": "DUMMY-SECRET-456"}
	getenv := func(name string) string { return env[name] }

	tests := []struct {
		name    string
		names   []string
		want    map[string]string
		wantErr string
	}{
		{name: "none declared", names: nil, want: map[string]string{}},
		{name: "all set", names: []string{"SET", "ALSO"}, want: env},
		{name: "names the missing one", names: []string{"SET", "MISSING"}, wantErr: "secret not set in the environment: MISSING"},
		{name: "names every missing one", names: []string{"X", "Y"}, wantErr: "X, Y"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := SecretValues(tt.names, getenv)
			if tt.wantErr != "" {
				require.ErrorIs(t, err, ErrSecretUnset)
				require.ErrorContains(t, err, tt.wantErr)
				assert.NotContains(t, err.Error(), "DUMMY", "errors never carry a value")

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
