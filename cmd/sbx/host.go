// Host-side helpers.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

// safeGit operations.
var safeGit = []string{
	"-c", "core.hooksPath=/dev/null",
	"-c", "core.fsmonitor=false",
	"-c", "protocol.file.allow=never",
	"-c", "transfer.fsckObjects=true",
	"-c", "submodule.recurse=false",
	"-c", "fetch.recurseSubmodules=false",
}

// state is what sbx records between runs in state.json.
type state struct {
	Name  string `json:"name,omitempty"`  // the sandbox init created
	Clone string `json:"clone,omitempty"` // the checkout init ran from
}

func (a *app) loadState() (state, error) {
	var st state

	data, err := os.ReadFile(filepath.Join(a.stateDir, "state.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}

	if err != nil {
		return st, fmt.Errorf("reading state: %w", err)
	}

	if err := json.Unmarshal(data, &st); err != nil {
		return st, fmt.Errorf("parsing state: %w", err)
	}

	return st, nil
}

// saveState writes the state.
func (a *app) saveState(st state) (bool, error) {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return false, fmt.Errorf("encoding state: %w", err)
	}

	return writeIfChanged(filepath.Join(a.stateDir, "state.json"), append(data, '\n'))
}

// lock sets lock on the state directory.
func (a *app) lock() (func(), error) {
	f, err := os.OpenFile(filepath.Join(a.stateDir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening the lock: %w", err)
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()

		return nil, fmt.Errorf("taking the lock: %w", err)
	}

	return func() { _ = f.Close() }, nil // closing releases the flock
}

// command creates a child process that logs to stderr.
func command(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // argv only, never a shell
	cmd.Stderr = os.Stderr

	return cmd
}

// git runs host git with the safe flags and an environment without GIT_*.
func git(ctx context.Context, dir string, args ...string) *exec.Cmd {
	full := append(append([]string{"-C", dir}, safeGit...), args...)
	cmd := exec.CommandContext(ctx, "git", full...) //nolint:gosec // argv only, never a shell

	cmd.Env = append(scrubEnv(os.Environ()), "GIT_TERMINAL_PROMPT=0")
	cmd.Stderr = os.Stderr

	return cmd
}

// gitOut runs a git command and returns its trimmed stdout.
func gitOut(ctx context.Context, dir string, args ...string) (string, error) {
	out, err := git(ctx, dir, args...).Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}

	return strings.TrimSpace(string(out)), nil
}

// scrubEnv drops GIT_* variables, which could redirect git to another repository, config or helper.
func scrubEnv(env []string) []string {
	return slices.DeleteFunc(slices.Clone(env), func(kv string) bool {
		return strings.HasPrefix(kv, "GIT_")
	})
}

var errNotCheckout = errors.New("run sbx from the agent-sandbox checkout")

// repoRoot returns the working directory, which contains config.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("finding the working directory: %w", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "config", "sandbox.toml")); err != nil {
				return "", errNotCheckout
			}

			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errNotCheckout
		}

		dir = parent
	}
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
