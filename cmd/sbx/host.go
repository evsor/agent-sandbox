// Host-side helpers.

package main

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
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

// state is what sbx records between runs in state.json. Fields older versions wrote, such as clone and rebuilt_sha, are ignored.
type state struct {
	Name      string            `json:"name,omitempty"`       // the sandbox init or rebuild created
	ConfigDir string            `json:"config_dir,omitempty"` // the user config dir sbx config wrote
	Image     string            `json:"image,omitempty"`      // the image tag it was rebuilt with
	Repos     map[string]string `json:"repos,omitempty"`      // the GitHub repo each guest repo ships to
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

// updateState applies change to the recorded state, saves it and reports the state file as made or ok.
func (a *app) updateState(change func(*state)) error {
	st, err := a.loadState()
	if err != nil {
		return err
	}

	change(&st)

	changed, err := a.saveState(st)
	if err != nil {
		return err
	}

	status := "ok"
	if changed {
		status = "made"
	}

	a.report(status, a.statePath())

	return nil
}

// lock takes the lock on the state directory.
func (a *app) lock() (func(), error) {
	return hostfs.Lock(filepath.Join(a.stateDir, "lock"))
}

// command creates a child process that logs to stderr and runs without the declared secrets.
func (a *app) command(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // argv only, never a shell
	cmd.Env = scrubEnv(os.Environ(), a.declared, false)
	cmd.Stderr = os.Stderr

	return cmd
}

// git runs host git with the safe flags and an environment without GIT_* or the declared secrets.
func (a *app) git(ctx context.Context, dir string, args ...string) *exec.Cmd {
	full := append(append([]string{"-C", dir}, safeGit...), args...)
	cmd := a.command(ctx, "git", full...)

	cmd.Env = append(scrubEnv(os.Environ(), a.declared, true), "GIT_TERMINAL_PROMPT=0")

	return cmd
}

// gitOut runs a git command and returns its trimmed stdout.
func (a *app) gitOut(ctx context.Context, dir string, args ...string) (string, error) {
	out, err := a.git(ctx, dir, args...).Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}

	return strings.TrimSpace(string(out)), nil
}

// scrubEnv drops the secrets and, with dropGit, GIT_* variables, which could redirect git to another repository, config or helper.
func scrubEnv(env, secrets []string, dropGit bool) []string {
	return slices.DeleteFunc(slices.Clone(env), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")

		return slices.Contains(secrets, name) || (dropGit && strings.HasPrefix(name, "GIT_"))
	})
}

// ask prints question and reports whether the answer is yes.
func (a *app) ask(question string) bool {
	return strings.EqualFold(a.prompt(question+" [y/N] "), "y")
}

// prompt prints question and returns the answer. EOF counts as an empty answer.
func (a *app) prompt(question string) string {
	fmt.Fprint(a.out, question)

	line, _ := a.in.ReadString('\n')

	return strings.TrimSpace(line)
}

// appliedDir holds a copy of the user config dir as it was at the last rebuild that verified.
func (a *app) appliedDir() string {
	return filepath.Join(a.stateDir, "applied")
}

// readTree reads every file under dir, keyed by its slash-separated path relative to dir.
func readTree(dir string) (map[string][]byte, error) {
	fsys := os.DirFS(dir)
	tree := map[string][]byte{}

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}

		tree[path] = data

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}

	return tree, nil
}

// diffTrees returns the paths, sorted, whose content differs between the trees or that only one of them has.
func diffTrees(a, b map[string][]byte) []string {
	var paths []string

	for path, data := range a {
		if other, ok := b[path]; !ok || !bytes.Equal(data, other) {
			paths = append(paths, path)
		}
	}

	for path := range b {
		if _, ok := a[path]; !ok {
			paths = append(paths, path)
		}
	}

	slices.Sort(paths)

	return paths
}

// saveApplied replaces the applied dir with tree, written to a new directory first so a failed copy leaves the old one.
func (a *app) saveApplied(tree map[string][]byte) error {
	tmp, err := os.MkdirTemp(a.stateDir, "applied-")
	if err != nil {
		return fmt.Errorf("creating a temporary directory: %w", err)
	}

	defer func() { _ = os.RemoveAll(tmp) }()

	for path, data := range tree {
		full := filepath.Join(tmp, filepath.FromSlash(path))

		if err := hostfs.EnsureDir(filepath.Dir(full)); err != nil {
			return err
		}

		if _, err := hostfs.WriteIfChanged(full, data); err != nil {
			return err
		}
	}

	if err := os.RemoveAll(a.appliedDir()); err != nil {
		return fmt.Errorf("removing the old %s: %w", a.appliedDir(), err)
	}

	if err := os.Rename(tmp, a.appliedDir()); err != nil {
		return fmt.Errorf("saving %s: %w", a.appliedDir(), err)
	}

	return nil
}
