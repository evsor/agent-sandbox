// The rebuild command: rebuilds the image from the user config dir, checks it, recreates the sandbox with its volumes kept, verifies
// it, and records the spec it applied.

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"

	"github.com/spf13/cobra"

	"github.com/evsor/agent-sandbox/internal/config"
	"github.com/evsor/agent-sandbox/internal/hostfs"
)

func newRebuildCmd(a *app) *cobra.Command {
	return newCmd("rebuild", "Rebuild the image from the config dir and recreate the sandbox; volumes are kept", a.rebuild)
}

// rebuild builds and checks the image from the user config dir, asks if anything needs a look, recreates the sandbox and verifies it.
func (a *app) rebuild(ctx context.Context) error {
	s, err := loadSpec(a.configDir)
	if err != nil {
		return err
	}

	a.useSpecName(s)

	secrets, err := config.SecretValues(s.cfg.SecretNames(), a.secret)
	if err != nil {
		return err
	}

	if err := s.check(); err != nil {
		return err
	}

	a.report("ok", "policy check: "+s.path())

	tag, err := s.imageTag()
	if err != nil {
		return err
	}

	hash, err := dirHash(s.dir)
	if err != nil {
		return err
	}

	// Always rebuilt and checked, whatever msb holds under the tag.
	if err := a.ensureImage(ctx, s, tag, true); err != nil {
		return err
	}

	changed := a.showChanges(s.cfg)

	if err := a.confirmSessions(ctx, "Recreating the sandbox", changed); err != nil {
		return err
	}

	if err := a.createSandbox(ctx, s, tag, secrets, true); err != nil {
		return err
	}

	a.report("made", "sandbox "+a.name)

	if _, err := a.ownMounts(ctx, s); err != nil {
		return err
	}

	a.report("ok", "volume roots owned by node")

	if err := a.verify(ctx); err != nil {
		last := "the last good sandbox.toml is " + a.appliedPath()
		if exists, _ := hostfs.Exists(a.appliedPath()); !exists {
			last = "no earlier create was verified"
		}

		return fmt.Errorf("%w\nVERIFY FAILED: fix the config in %s and run sbx rebuild; %s", err, s.dir, last)
	}

	if err := a.recordApplied(s, hash, tag); err != nil {
		return err
	}

	fmt.Fprintf(a.out, "rebuilt from %s (%s)\n", s.dir, tag)

	return nil
}

// showChanges prints the allowed hosts, addresses and secret bindings added or removed since the last verified create, all of them if
// its sandbox.toml is missing or can't be read, and reports whether there were any.
func (a *app) showChanges(target *config.Config) bool {
	old, _, err := config.Load(a.appliedPath())

	since := "since the last verified create"

	switch {
	case errors.Is(err, fs.ErrNotExist):
		since = "no earlier create was verified"
	case err != nil:
		since = err.Error()
	}

	changes := allowChanges(old, target)
	if len(changes) == 0 {
		return false
	}

	fmt.Fprintf(a.out, "Allowlist and secret changes (%s):\n", since)

	for _, c := range changes {
		fmt.Fprintln(a.out, "  "+c)
	}

	return true
}

// allowChanges lists what target allows that old doesn't (+) and the reverse (-). A nil old allows nothing.
func allowChanges(old, target *config.Config) []string {
	before, after := allows(old), allows(target)

	var changes []string

	for _, x := range after {
		if !slices.Contains(before, x) {
			changes = append(changes, "+ "+x)
		}
	}

	for _, x := range before {
		if !slices.Contains(after, x) {
			changes = append(changes, "- "+x)
		}
	}

	return changes
}

// allows describes each allowed host, allowed address and secret binding, one line each.
func allows(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}

	var out []string

	for _, d := range cfg.Network.AllowDomains {
		out = append(out, fmt.Sprintf("allow_domains %q", d))
	}

	for _, ip := range cfg.Network.AllowIPs {
		out = append(out, fmt.Sprintf("allow_ips %q", ip))
	}

	for _, s := range cfg.Secrets {
		out = append(out, fmt.Sprintf("secret %q hosts %q header_fields %q passthrough %q", s.Name, s.Allow, s.HeaderFields, s.Passthrough))
	}

	return out
}
