// The init command: writes the example config into the user config dir where a file is missing, checks the host and the spec, writes
// sbx's SSH files, then makes sure the image and the sandbox exist, the sandbox runs and node owns the volume roots, and ends by
// verifying the sandbox.

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode"

	msb "github.com/superradcompany/microsandbox/sdk/go"

	"github.com/spf13/cobra"

	example "github.com/evsor/agent-sandbox/config"
	"github.com/evsor/agent-sandbox/internal/config"
	"github.com/evsor/agent-sandbox/internal/ssh"
)

const initLong = `Writes each example file missing from the user config dir (default ~/.config/agent-sandbox), never changing one that
exists, and records the dir. When it writes image/etc/gitconfig, it asks for the git name and email for commits in the sandbox,
offering the host's git user.name and user.email. Then it checks the host, builds the image from the config dir, creates and
starts the sandbox, and verifies it. Re-runnable: it creates only what's missing. Edit the config dir, then run sbx rebuild.`

func newInitCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write the example config if missing, build the image from the config dir, create and start the sandbox, and verify it",
		Long:  initLong,
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.init(cmd)
		},
	}

	cmd.Flags().String("git-name", "", "git user.name in the sandbox, when init writes image/etc/gitconfig (skips the question)")
	cmd.Flags().String("git-email", "", "git user.email in the sandbox, when init writes image/etc/gitconfig (skips the question)")

	return cmd
}

func (a *app) init(cmd *cobra.Command) error {
	ctx := cmd.Context()

	seedChanged, err := a.seedConfig(cmd)
	if err != nil {
		return err
	}

	s, err := loadSpec(a.configDir)
	if err != nil {
		return err
	}

	a.useSpecName(s)

	secrets, err := config.SecretValues(s.cfg.SecretNames(), a.secret)
	if err != nil {
		return err
	}

	if err := a.checkPrerequisites(ctx); err != nil {
		return err
	}

	if err := s.check(); err != nil {
		return err
	}

	a.report("ok", "policy check: "+s.path())

	if err := a.setupSSH(ctx); err != nil {
		return err
	}

	tag, err := s.imageTag()
	if err != nil {
		return err
	}

	hash, err := dirHash(s.dir)
	if err != nil {
		return err
	}

	created, err := a.ensureSandbox(ctx, s, tag, secrets)
	if err != nil {
		return err
	}

	if err := a.recordName(seedChanged); err != nil {
		return err
	}

	if err := a.verify(ctx); err != nil {
		return err
	}

	// A sandbox that existed may not match the config dir: only rebuild records it then.
	if created {
		return a.recordApplied(s, hash, tag)
	}

	return nil
}

// recordName records the sandbox name in state.json and reports the file, made if seedConfig or this changed it.
func (a *app) recordName(seedChanged bool) error {
	st, err := a.loadState()
	if err != nil {
		return err
	}

	st.Name = a.name

	changed, err := a.saveState(st)
	if err != nil {
		return err
	}

	status := "ok"
	if changed || seedChanged {
		status = "made"
	}

	a.report(status, a.statePath())

	return nil
}

// seedConfig writes the example files the user config dir lacks, asking for the git identity only when it writes the gitconfig, and
// records the dir in state.json. It reports whether it changed state.json.
func (a *app) seedConfig(cmd *cobra.Command) (bool, error) {
	noIdentity := false

	files, err := config.Seed(a.configDir, example.FS, func(path string, data []byte) ([]byte, error) {
		if path != config.GitconfigFile {
			return data, nil
		}

		name := a.gitIdentity(cmd, "git-name", "user.name")
		email := a.gitIdentity(cmd, "git-email", "user.email")
		noIdentity = name == "" || email == ""

		return config.FillIdentity(data, name, email)
	})
	if err != nil {
		return false, fmt.Errorf("writing the example config into %s: %w", a.configDir, err)
	}

	made := false

	for _, f := range files {
		status := "ok"
		if f.Made {
			status, made = "made", true
		}

		a.report(status, filepath.Join(a.configDir, filepath.FromSlash(f.Path)))
	}

	if noIdentity {
		fmt.Fprintf(a.out, "\nWARNING: git name or email missing: commits in the sandbox are refused until you set both under [user] in %s\n",
			filepath.Join(a.configDir, filepath.FromSlash(config.GitconfigFile)))
	}

	if made {
		fmt.Fprintf(a.out, "\nThe sandbox config is in %s: edit it, then run sbx rebuild\n\n", a.configDir)
	}

	st, err := a.loadState()
	if err != nil {
		return false, err
	}

	st.ConfigDir = a.configDir

	return a.saveState(st)
}

// gitIdentity returns the flag's value if it was given, else asks, offering the host's git setting key, which Enter or EOF takes.
func (a *app) gitIdentity(cmd *cobra.Command, flag, key string) string {
	if cmd.Flags().Changed(flag) {
		value, _ := cmd.Flags().GetString(flag) // a string flag init defines

		return value
	}

	def := a.hostGitConfig(cmd.Context(), key)

	if got := a.prompt(fmt.Sprintf("git %s for commits in the sandbox [%s]: ", key, def)); got != "" {
		return got
	}

	return def
}

func (a *app) checkPrerequisites(ctx context.Context) error {
	kvm, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("KVM is not usable: %w", err)
	}

	_ = kvm.Close()

	for _, tool := range []string{"docker", "git", "gh", "ssh", "ssh-keygen"} {
		if _, err := exec.LookPath(tool); err != nil {
			return fmt.Errorf("%s is required: %w", tool, err)
		}
	}

	if err := a.command(ctx, "docker", "version", "--format", "{{.Server.Version}}").Run(); err != nil {
		return fmt.Errorf("docker is not usable: %w", err)
	}

	a.report("ok", "prerequisites: KVM, msb "+msb.SDKVersion()+", docker, git, gh, ssh, ssh-keygen")

	return nil
}

// setupSSH writes sbx's SSH files with its real paths and prints the Include line when the ssh config changes.
func (a *app) setupSSH(ctx context.Context) error {
	// The ssh config runs from any directory, so its paths must be absolute.
	stateDir, err := filepath.Abs(a.stateDir)
	if err != nil {
		return fmt.Errorf("finding the state directory: %w", err)
	}

	sbx, err := sbxPath()
	if err != nil {
		return err
	}

	proxy := sbx + " connect --name " + a.name

	if a.v.GetString("state-dir") != "" {
		proxy += " --state-dir " + stateDir
	}

	dir := ssh.Dir(stateDir)

	made, err := ssh.Setup(ctx, ssh.Options{Dir: dir, Name: a.name, ProxyCommand: proxy})
	if err != nil {
		return fmt.Errorf("setting up the ssh files: %w", err)
	}

	for _, path := range made {
		a.report("made", path)

		// sbx never reads ~/.ssh, so it can't tell whether the Include is already there.
		if filepath.Base(path) == ssh.Config {
			fmt.Fprintf(a.out, "\nAdd this line at the top of ~/.ssh/config, once:\n  Include %s\n\n", path)
		}
	}

	a.report("ok", "ssh files in "+dir)

	return nil
}

// sbxPath returns the running sbx's path, which the ssh config runs, so sbx can be installed anywhere.
func sbxPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("finding sbx's path: %w", err)
	}

	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("finding sbx's path: %w", err)
	}

	if strings.ContainsFunc(exe, unicode.IsSpace) {
		return "", fmt.Errorf("sbx is at %q: ssh runs ProxyCommand through a shell, so install sbx at a path without whitespace", exe)
	}

	return exe, nil
}

// ensureSandbox creates the sandbox if it doesn't exist, or starts it if it's stopped, then gives node the mount roots. It reports
// whether it created the sandbox.
func (a *app) ensureSandbox(ctx context.Context, s *spec, tag string, secrets map[string]string) (bool, error) {
	h, err := a.handle(ctx)
	created, started := false, false

	switch {
	case msb.IsKind(err, msb.ErrSandboxNotFound):
		if err := a.ensureImage(ctx, s, tag, false); err != nil {
			return false, err
		}

		if err := a.createSandbox(ctx, s, tag, secrets, false); err != nil {
			return false, err
		}

		created = true

		a.report("made", "sandbox "+a.name)
	case err != nil:
		return false, err
	case h.Status() == msb.SandboxStatusRunning:
		a.report("ok", "sandbox "+a.name+" is running")
	default:
		started = true
	}

	changed, err := a.ownMounts(ctx, s)
	if err != nil {
		return created, err
	}

	if started {
		a.report("made", "sandbox "+a.name+" started")
	}

	for _, target := range changed {
		a.report("made", target+" owned by node")
	}

	if len(changed) == 0 {
		a.report("ok", "volume roots owned by node")
	}

	return created, nil
}

func (a *app) report(status, what string) {
	fmt.Fprintf(a.out, "%-5s %s\n", status, what)
}
