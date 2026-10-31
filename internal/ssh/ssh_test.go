package ssh

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func options(dir string) Options {
	return Options{Dir: dir, Name: "test-box", ProxyCommand: "/bin/sbx connect --name test-box"}
}

func read(t *testing.T, dir, name string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // the test's own temporary directory
	require.NoError(t, err)

	return string(data)
}

func paths(dir string, names ...string) []string {
	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, filepath.Join(dir, name))
	}

	return out
}

func TestSetup(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "ssh")

	made, err := Setup(t.Context(), options(dir))
	require.NoError(t, err)

	assert.Equal(t, paths(dir, clientKey, HostKey, AuthorizedKeys, knownHosts, Config), made)

	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())

	for _, name := range []string{clientKey, HostKey, AuthorizedKeys, knownHosts, Config} {
		info, err := os.Stat(filepath.Join(dir, name))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), name)
	}

	assert.Equal(t, read(t, dir, clientKey+".pub"), read(t, dir, AuthorizedKeys))

	host := strings.Fields(read(t, dir, HostKey+".pub"))
	require.GreaterOrEqual(t, len(host), 2)
	assert.Equal(t, "test-box "+host[0]+" "+host[1]+"\n", read(t, dir, knownHosts))

	want := "Host test-box\n" +
		"  ProxyCommand /bin/sbx connect --name test-box\n" +
		"  User node\n" +
		"  IdentityFile " + dir + "/id_ed25519\n" +
		"  IdentitiesOnly yes\n" +
		"  ForwardAgent no\n" +
		"  UserKnownHostsFile " + dir + "/known_hosts\n" +
		"  StrictHostKeyChecking yes\n" +
		"  HostKeyAlias test-box\n" +
		"  ServerAliveInterval 30\n" +
		"  ServerAliveCountMax 4\n"
	assert.Equal(t, want, read(t, dir, Config))
}

func TestSetup_rerun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		change func(*Options)
		want   []string
	}{
		{name: "nothing changed", change: func(*Options) {}},
		{
			name:   "new proxy command",
			change: func(o *Options) { o.ProxyCommand += " --state-dir /state" },
			want:   []string{Config},
		},
		{
			name:   "new sandbox name",
			change: func(o *Options) { o.Name = "test-other" },
			want:   []string{knownHosts, Config},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			o := options(t.TempDir())

			_, err := Setup(t.Context(), o)
			require.NoError(t, err)

			clientPriv, hostPriv := read(t, o.Dir, clientKey), read(t, o.Dir, HostKey)

			tt.change(&o)

			made, err := Setup(t.Context(), o)
			require.NoError(t, err)

			assert.ElementsMatch(t, paths(o.Dir, tt.want...), made)
			assert.Equal(t, clientPriv, read(t, o.Dir, clientKey), "the client key is kept")
			assert.Equal(t, hostPriv, read(t, o.Dir, HostKey), "the host key is kept")
		})
	}
}

func TestSetup_errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prepare func(t *testing.T, dir string)
		wantErr string
	}{
		{
			name: "directory is a file",
			prepare: func(t *testing.T, dir string) {
				t.Helper()
				require.NoError(t, os.WriteFile(dir, nil, 0o600))
			},
			wantErr: "creating",
		},
		{
			name: "host key without its public key",
			prepare: func(t *testing.T, dir string) {
				t.Helper()
				require.NoError(t, os.Mkdir(dir, 0o700))
				require.NoError(t, os.WriteFile(filepath.Join(dir, HostKey), []byte("DUMMY"), 0o600))
			},
			wantErr: "reading the host key",
		},
		{
			name: "malformed host public key",
			prepare: func(t *testing.T, dir string) {
				t.Helper()
				require.NoError(t, os.Mkdir(dir, 0o700))
				require.NoError(t, os.WriteFile(filepath.Join(dir, HostKey), []byte("DUMMY"), 0o600))
				require.NoError(t, os.WriteFile(filepath.Join(dir, HostKey+".pub"), []byte("ssh-ed25519"), 0o600))
			},
			wantErr: "malformed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := filepath.Join(t.TempDir(), "ssh")

			tt.prepare(t, dir)

			_, err := Setup(t.Context(), options(dir))
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
