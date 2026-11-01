// Host-side helpers.

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/evsor/agent-sandbox/internal/hostfs"
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
	Name       string `json:"name,omitempty"`        // the sandbox init created
	Clone      string `json:"clone,omitempty"`       // the checkout init ran from
	RebuiltSHA string `json:"rebuilt_sha,omitempty"` // the commit last rebuilt
}

// statePath is the state file.
func (a *app) statePath() string {
	return filepath.Join(a.stateDir, "state.json")
}

func (a *app) loadState() (state, error) {
	var st state

	err := hostfs.ReadJSON(a.statePath(), &st)

	return st, err
}

// saveState writes the state and reports whether it changed.
func (a *app) saveState(st state) (bool, error) {
	return hostfs.WriteJSON(a.statePath(), st)
}

// lock takes the lock on the state directory.
func (a *app) lock() (func(), error) {
	return hostfs.Lock(filepath.Join(a.stateDir, "lock"))
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
	cmd := command(ctx, "git", full...)

	cmd.Env = append(scrubEnv(os.Environ()), "GIT_TERMINAL_PROMPT=0")

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
			if _, err := os.Stat(filepath.Join(dir, specPath)); err != nil {
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
