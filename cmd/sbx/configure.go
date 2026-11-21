// The config command: copies the example config into the user config dir, filling in a few values, and never changes a file that
// exists.

package main

import (
	"fmt"
	"io/fs"
	"maps"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/evsor/agent-sandbox/example"
	"github.com/evsor/agent-sandbox/internal/config"
	"github.com/evsor/agent-sandbox/internal/hostfs"
	"github.com/evsor/agent-sandbox/internal/policy"
)

const gitconfigFile = "image/etc/gitconfig"

func newConfigCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Write the example config to the config dir, asking for a few values; existing files are kept",
		Long: `Write the example config to the config dir, asking for a few values; existing files are kept.

It asks for the config dir unless --config-dir, SBX_CONFIG_DIR or an earlier sbx config chose it, and only for the values of the
files it writes, showing each default: press Enter to take it. A flag skips its question.
Edit the files in place afterwards, then run sbx init, or sbx rebuild for an existing sandbox.`,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.configure(cmd)
		},
	}

	flags := cmd.Flags()
	flags.String("git-name", "", "git user.name in the sandbox (default empty: commits are refused)")
	flags.String("git-email", "", "git user.email in the sandbox (default empty: commits are refused)")
	flags.String("cpus", "", "CPUs (default: the example's)")
	flags.String("memory-mib", "", "memory in MiB (default: the example's)")

	return cmd
}

func (a *app) configure(cmd *cobra.Command) error {
	dir := a.configDir
	if !a.configDirOK {
		dir = a.answer("config dir", dir)
	}

	dir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("finding the config dir: %w", err)
	}

	files, missing, err := exampleFiles(dir)
	if err != nil {
		return err
	}

	noIdentity := false

	// Every value is checked before anything is written.
	if missing[gitconfigFile] {
		name := a.flagOrAnswer(cmd, "git-name", "git name (empty: commits in the sandbox are refused)", "")
		email := a.flagOrAnswer(cmd, "git-email", "git email (empty: commits in the sandbox are refused)", "")

		if files[gitconfigFile], err = config.FillGitconfig(files[gitconfigFile], name, email); err != nil {
			return err
		}

		noIdentity = name == "" || email == ""
	}

	if missing[specFile] {
		if files[specFile], err = a.fillSpec(cmd, files[specFile]); err != nil {
			return err
		}
	}

	if err := a.writeMissing(dir, files, missing); err != nil {
		return err
	}

	if err := a.updateState(func(st *state) { st.ConfigDir = dir }); err != nil {
		return err
	}

	if noIdentity {
		fmt.Fprintf(a.out, "\nNo git identity: commits in the sandbox are refused until you add user.name and user.email to %s\n",
			filepath.Join(dir, gitconfigFile))
	}

	return nil
}

// writeMissing writes the files dir lacks, reporting each file as made or ok.
func (a *app) writeMissing(dir string, files map[string][]byte, missing map[string]bool) error {
	for _, path := range slices.Sorted(maps.Keys(files)) {
		full := filepath.Join(dir, filepath.FromSlash(path))

		if !missing[path] {
			a.report("ok", full)

			continue
		}

		if err := hostfs.EnsureDir(filepath.Dir(full)); err != nil {
			return err
		}

		if _, err := hostfs.WriteIfChanged(full, files[path]); err != nil {
			return err
		}

		a.report("made", full)
	}

	return nil
}

// exampleFiles returns the example's files by path, and which of them dir lacks.
func exampleFiles(dir string) (map[string][]byte, map[string]bool, error) {
	files, missing := map[string][]byte{}, map[string]bool{}

	err := fs.WalkDir(example.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		if files[path], err = fs.ReadFile(example.FS, path); err != nil {
			return err
		}

		exists, err := hostfs.Exists(filepath.Join(dir, filepath.FromSlash(path)))
		missing[path] = !exists

		return err
	})
	if err != nil {
		return nil, nil, fmt.Errorf("reading the example: %w", err)
	}

	return files, missing, nil
}

// fillSpec asks for the sandbox name, CPUs and memory, defaulting to the example's, and returns the filled spec once it passes the
// policy check.
func (a *app) fillSpec(cmd *cobra.Command, raw []byte) ([]byte, error) {
	def, err := config.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("the example %s: %w", specFile, err)
	}

	v := config.SpecValues{Name: a.name}
	if !a.nameSet {
		v.Name = a.answer("sandbox name", def.Name)
	}

	v.CPUs = a.flagOrAnswer(cmd, "cpus", "cpus", strconv.Itoa(int(def.CPUs)))
	v.MemoryMiB = a.flagOrAnswer(cmd, "memory-mib", "memory_mib", strconv.FormatUint(uint64(def.MemoryMiB), 10))

	filled, cfg, err := config.FillSpec(raw, v)
	if err != nil {
		return nil, err
	}

	if err := policy.Check(policy.FromConfig(cfg, filled)); err != nil {
		return nil, err
	}

	return filled, nil
}

// flagOrAnswer returns the flag's value if it was given, else the answer to the question.
func (a *app) flagOrAnswer(cmd *cobra.Command, flag, question, def string) string {
	if cmd.Flags().Changed(flag) {
		value, _ := cmd.Flags().GetString(flag) // a string flag this command defines

		return value
	}

	return a.answer(question, def)
}

// answer asks question showing def, which an empty answer or EOF takes.
func (a *app) answer(question, def string) string {
	if got := a.prompt(fmt.Sprintf("%s [%s]: ", question, def)); got != "" {
		return got
	}

	return def
}
