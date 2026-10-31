// Package ssh sets up sbx's own SSH files in its state dir: the client and host keys, authorized_keys, known_hosts and the ssh config.
// It never touches ~/.ssh.
package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// The files in the SSH directory that sbx's commands use.
const (
	HostKey        = "host_ed25519"
	AuthorizedKeys = "authorized_keys"
	Config         = "config"
)

const (
	clientKey  = "id_ed25519"
	knownHosts = "known_hosts"
)

const configTemplate = `Host %[1]s
  ProxyCommand %[2]s
  User node
  IdentityFile %[3]s/id_ed25519
  IdentitiesOnly yes
  ForwardAgent no
  UserKnownHostsFile %[3]s/known_hosts
  StrictHostKeyChecking yes
  HostKeyAlias %[1]s
  ServerAliveInterval 30
  ServerAliveCountMax 4
`

// Options says what Setup writes.
type Options struct {
	Dir          string // the SSH directory, absolute: the ssh config runs from any directory
	Name         string // the sandbox name: the ssh config's Host alias and the known_hosts entry
	ProxyCommand string // the command ssh runs to reach the sandbox
}

// Dir is the SSH directory under a state dir.
func Dir(stateDir string) string {
	return filepath.Join(stateDir, "ssh")
}

// Setup creates what's missing and rewrites what changed. It returns the paths it created or changed, with the ssh config last.
func Setup(ctx context.Context, o Options) ([]string, error) {
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating %s: %w", o.Dir, err)
	}

	var made []string

	for _, key := range []string{clientKey, HostKey} {
		path := filepath.Join(o.Dir, key)

		created, err := makeKey(ctx, path)
		if err != nil {
			return nil, err
		}

		if created {
			made = append(made, path)
		}
	}

	files, err := render(o)
	if err != nil {
		return nil, err
	}

	for _, name := range []string{AuthorizedKeys, knownHosts, Config} {
		path := filepath.Join(o.Dir, name)

		changed, err := writeIfChanged(path, []byte(files[name]))
		if err != nil {
			return nil, err
		}

		if changed {
			made = append(made, path)
		}
	}

	return made, nil
}

// makeKey creates an ed25519 key unless it exists. No passphrase: whoever can read it can already run msb exec.
func makeKey(ctx context.Context, path string) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return false, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("checking %s: %w", path, err)
	}

	cmd := exec.CommandContext(ctx, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "sbx-"+filepath.Base(path), "-f", path) //nolint:gosec // argv only, never a shell

	// It needs no environment, and sbx's may hold secrets.
	cmd.Env = []string{}

	if out, err := cmd.CombinedOutput(); err != nil {
		return false, fmt.Errorf("ssh-keygen %s: %w: %s", path, err, strings.TrimSpace(string(out)))
	}

	return true, nil
}

// render returns authorized_keys (the client key), known_hosts (the host key, so no prompt even after a recreate) and the ssh config.
func render(o Options) (map[string]string, error) {
	clientPub, err := os.ReadFile(filepath.Join(o.Dir, clientKey+".pub"))
	if err != nil {
		return nil, fmt.Errorf("reading the client key: %w", err)
	}

	hostPub, err := os.ReadFile(filepath.Join(o.Dir, HostKey+".pub"))
	if err != nil {
		return nil, fmt.Errorf("reading the host key: %w", err)
	}

	fields := strings.Fields(string(hostPub))
	if len(fields) < 2 {
		return nil, errors.New("the host public key is malformed")
	}

	return map[string]string{
		AuthorizedKeys: string(clientPub),
		knownHosts:     o.Name + " " + fields[0] + " " + fields[1] + "\n",
		Config:         fmt.Sprintf(configTemplate, o.Name, o.ProxyCommand, o.Dir),
	}, nil
}

// writeIfChanged writes data with mode 0600.
func writeIfChanged(path string, data []byte) (bool, error) {
	old, err := os.ReadFile(path) //nolint:gosec // a path sbx builds under its own state dir
	if err == nil && bytes.Equal(old, data) {
		return false, nil
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return false, fmt.Errorf("writing %s: %w", path, err)
	}

	return true, nil
}
