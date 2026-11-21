// The init command: checks the host and the user config's spec, writes sbx's SSH files, then makes sure the image and the sandbox
// exist, the sandbox runs and node owns the volume roots, and ends by verifying the sandbox.

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

	"github.com/evsor/agent-sandbox/internal/ssh"
)

func newInitCmd(a *app) *cobra.Command {
	return newCmd("init", "Check the host, build the image from the config dir, create and start the sandbox, and verify it (re-runnable)", a.init)
}

func (a *app) init(ctx context.Context) error {
	s, secrets, err := a.checkedSpec()
	if err != nil {
		return err
	}

	if err := a.checkPrerequisites(ctx); err != nil {
		return err
	}

	if err := a.setupSSH(ctx); err != nil {
		return err
	}

	created, err := a.ensureSandbox(ctx, s, imageTag(s), secrets)
	if err != nil {
		return err
	}

	if err := a.updateState(func(st *state) { st.Name = a.name }); err != nil {
		return err
	}

	if err := a.verify(ctx); err != nil {
		return err
	}

	// A sandbox init didn't create may run on another config, so only a new one makes this config the applied one.
	if !created {
		return nil
	}

	if err := a.saveApplied(s.tree); err != nil {
		return err
	}

	a.report("made", a.appliedDir())

	return nil
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

	// The ssh config runs the sbx that wrote it, wherever it is installed.
	sbx, err := os.Executable()
	if err != nil {
		return fmt.Errorf("finding sbx's path: %w", err)
	}

	if sbx, err = filepath.EvalSymlinks(sbx); err != nil {
		return fmt.Errorf("finding sbx's path: %w", err)
	}

	// ssh hands the ProxyCommand to a shell, which would split the path.
	if strings.ContainsFunc(sbx, unicode.IsSpace) {
		return fmt.Errorf("sbx is at %q: move it to a path without whitespace, then run sbx init again", sbx)
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

// ensureSandbox creates the sandbox if it doesn't exist, or starts it if it's stopped, then gives node the mount roots. It reports
// whether it created the sandbox.
func (a *app) ensureSandbox(ctx context.Context, s *spec, tag string, secrets map[string]string) (bool, error) {
	h, err := a.handle(ctx)
	created, started := false, false

	switch {
	case msb.IsKind(err, msb.ErrSandboxNotFound):
		if err := a.ensureImage(ctx, s, tag); err != nil {
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
		return false, err
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
