// The init command: checks the host and the spec, then makes sure the image and the sandbox exist, the sandbox runs and node owns the
// volume roots, and ends by verifying the sandbox.

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	msb "github.com/superradcompany/microsandbox/sdk/go"

	"github.com/spf13/cobra"
)

func newInitCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Check the host, build the image from config/, create and start the sandbox, and verify it (re-runnable)",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.init(cmd.Context())
		},
	}
}

func (a *app) init(ctx context.Context) error {
	repo, err := repoRoot()
	if err != nil {
		return err
	}

	s, err := loadSpec(repo)
	if err != nil {
		return err
	}

	a.useSpecName(s)

	if err := a.checkPrerequisites(ctx); err != nil {
		return err
	}

	if err := s.check(); err != nil {
		return err
	}

	a.report("ok", "policy check: config/sandbox.toml")

	tag, err := imageTag(ctx, s)
	if err != nil {
		return err
	}

	if err := a.ensureSandbox(ctx, s, tag); err != nil {
		return err
	}

	st, err := a.loadState()
	if err != nil {
		return err
	}

	st.Name, st.Clone = a.name, repo

	changed, err := a.saveState(st)
	if err != nil {
		return err
	}

	status := "ok"
	if changed {
		status = "made"
	}

	a.report(status, filepath.Join(a.stateDir, "state.json"))

	return a.verify(ctx)
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

	if err := command(ctx, "docker", "version", "--format", "{{.Server.Version}}").Run(); err != nil {
		return fmt.Errorf("docker is not usable: %w", err)
	}

	a.report("ok", "prerequisites: KVM, msb "+msb.SDKVersion()+", docker, git, gh, ssh, ssh-keygen")

	return nil
}

// ensureSandbox creates the sandbox if it doesn't exist, or starts it if it's stopped, then gives node the mount roots.
func (a *app) ensureSandbox(ctx context.Context, s *spec, tag string) error {
	h, err := msb.GetSandbox(ctx, a.name)
	started := false

	switch {
	case msb.IsKind(err, msb.ErrSandboxNotFound):
		if err := a.ensureImage(ctx, s, tag); err != nil {
			return err
		}

		if err := a.createSandbox(ctx, s, tag); err != nil {
			return err
		}

		a.report("made", "sandbox "+a.name)
	case err != nil:
		return fmt.Errorf("finding sandbox %s: %w", a.name, err)
	case h.Status() == msb.SandboxStatusRunning:
		a.report("ok", "sandbox "+a.name+" is running")
	default:
		started = true
	}

	changed, err := a.ownMounts(ctx, s)
	if err != nil {
		return err
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

	return nil
}

func (a *app) report(status, what string) {
	fmt.Fprintf(a.out, "%-5s %s\n", status, what)
}
