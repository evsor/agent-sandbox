// The rebuild command: rebuilds the image from the user config dir, checks it, shows what changed since the last good config,
// recreates the sandbox with its volumes kept, verifies it and keeps a copy of the config it applied.

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/evsor/agent-sandbox/internal/config"
)

func newRebuildCmd(a *app) *cobra.Command {
	return newCmd("rebuild", "Rebuild the image and recreate the sandbox from the config dir; volumes are kept", a.rebuild)
}

// rebuild builds and checks the image, asks if anything needs a look, recreates the sandbox, verifies it and saves the config it
// applied.
func (a *app) rebuild(ctx context.Context) error {
	s, secrets, err := a.checkedSpec()
	if err != nil {
		return err
	}

	tag := imageTag(s)
	if err := a.ensureImage(ctx, s, tag); err != nil {
		return err
	}

	applied, err := readTree(a.appliedDir())
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	changed := a.showChanges(applied, s)

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
		if applied == nil {
			return fmt.Errorf("%w\nVERIFY FAILED; no earlier rebuild is recorded", err)
		}

		return fmt.Errorf("%w\nVERIFY FAILED; the last good config is in %s: copy it to %s and run sbx rebuild", err, a.appliedDir(), a.configDir)
	}

	if err := a.saveApplied(s.tree); err != nil {
		return err
	}

	a.report("made", a.appliedDir())

	if err := a.updateState(func(st *state) { st.Name, st.Image = a.name, tag }); err != nil {
		return err
	}

	fmt.Fprintf(a.out, "rebuilt %s from %s\n", tag, a.configDir)

	return nil
}

// showChanges prints the allowed hosts, addresses and secret bindings added or removed since the applied config, all of them if it
// is missing or its spec can't be read, then names the files that differ from it. It reports whether the allowlist or secrets changed.
func (a *app) showChanges(applied map[string][]byte, target *spec) bool {
	var old *config.Config

	since := "no earlier rebuild is recorded"

	if applied != nil {
		cfg, err := config.Parse(applied[specFile])
		if err != nil {
			since = fmt.Sprintf("the applied %s can't be read: %v", specFile, err)
		} else {
			old, since = cfg, "since the last rebuild"
		}
	}

	changes := allowChanges(old, target.cfg)
	if len(changes) > 0 {
		fmt.Fprintf(a.out, "Allowlist and secret changes (%s):\n", since)

		for _, c := range changes {
			fmt.Fprintln(a.out, "  "+c)
		}
	}

	if applied != nil {
		if files := diffTrees(applied, target.tree); len(files) > 0 {
			fmt.Fprintln(a.out, "Files changed since the last rebuild: "+strings.Join(files, ", "))
		}
	}

	return len(changes) > 0
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
