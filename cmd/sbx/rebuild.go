// The rebuild command: rebuilds the image from merged main in a clean worktree, checks it, recreates the sandbox with its volumes
// kept, and verifies it.

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/evsor/agent-sandbox/internal/config"
)

func newRebuildCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "rebuild [<sha>]",
		Short: "Rebuild the image and recreate the sandbox from merged main; volumes are kept",
		Args:  rebuildArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.rebuild(cmd.Context(), args)
		},
	}
}

// rebuildArgs rejects extra arguments as a usage error, so sbx exits 2.
func rebuildArgs(cmd *cobra.Command, args []string) error {
	if err := cobra.MaximumNArgs(1)(cmd, args); err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}

	return nil
}

func (a *app) rebuild(ctx context.Context, args []string) error {
	clone, err := repoRoot()
	if err != nil {
		return err
	}

	target, err := a.rebuildTarget(ctx, clone, args)
	if err != nil {
		return err
	}

	// The target may declare a secret that the clone's HEAD and the live sandbox don't, and its value must not reach the build.
	if cfg, err := a.specAt(ctx, clone, target); err == nil {
		a.declare(cfg.SecretNames()...)
	}

	tmp, err := os.MkdirTemp("", "sbx-rebuild-")
	if err != nil {
		return fmt.Errorf("creating a temporary directory: %w", err)
	}

	tree := filepath.Join(tmp, "tree")
	if err := a.git(ctx, clone, "worktree", "add", "--quiet", "--detach", tree, target).Run(); err != nil {
		_ = os.RemoveAll(tmp)

		return fmt.Errorf("creating a worktree at %.12s: %w", target, err)
	}

	defer func() {
		// Still runs after Ctrl-C has cancelled ctx.
		if err := a.git(context.WithoutCancel(ctx), clone, "worktree", "remove", "--force", tree).Run(); err != nil {
			slog.Warn("removing the worktree", "path", tree, "err", err)
		}

		_ = os.RemoveAll(tmp)
	}()

	return a.rebuildFrom(ctx, clone, tree, target)
}

// rebuildTarget refuses a dirty clone, fetches origin and returns the commit to build: origin/main, or the given commit if it is on
// origin/main's first-parent line.
func (a *app) rebuildTarget(ctx context.Context, clone string, args []string) (string, error) {
	dirty, err := a.gitOut(ctx, clone, "status", "--porcelain", "--untracked-files=no")
	if err != nil {
		return "", err
	}

	if dirty != "" {
		return "", fmt.Errorf("the operator clone %s has uncommitted changes: refusing to rebuild", clone)
	}

	if err := a.git(ctx, clone, "fetch", "--quiet", "origin").Run(); err != nil {
		return "", fmt.Errorf("fetching origin: %w", err)
	}

	main, err := a.gitOut(ctx, clone, "rev-parse", "origin/main")
	if err != nil {
		return "", err
	}

	if len(args) == 0 {
		return main, nil
	}

	target, err := a.gitOut(ctx, clone, "rev-parse", "--verify", "--end-of-options", args[0]+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("%q is not a commit: %w", args[0], err)
	}

	// Only main's own line of merges and direct commits: a commit from inside a merged branch can hold a config no review showed. A
	// rebase merge puts each of its commits on that line, so those are trusted one by one.
	line, err := a.gitOut(ctx, clone, "rev-list", "--first-parent", main)
	if err != nil {
		return "", err
	}

	if !slices.Contains(strings.Fields(line), target) {
		return "", fmt.Errorf("%.12s is not a merge or direct commit on origin/main: refusing to rebuild", target)
	}

	return target, nil
}

// rebuildFrom builds and checks the image from the worktree, asks if anything needs a look, recreates the sandbox and verifies it.
func (a *app) rebuildFrom(ctx context.Context, clone, tree, target string) error {
	s, err := loadSpec(tree)
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

	a.report("ok", "policy check: "+specPath)

	tag, err := a.imageTag(ctx, s)
	if err != nil {
		return err
	}

	// Always rebuilt: an init from a dirty checkout may have loaded an image under this tag.
	if err := a.ensureImage(ctx, s, tag, true); err != nil {
		return err
	}

	st, err := a.loadState()
	if err != nil {
		return err
	}

	changed := a.showChanges(ctx, clone, st.RebuiltSHA, s.cfg)

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
		if st.RebuiltSHA == "" {
			return fmt.Errorf("%w\nVERIFY FAILED after rebuilding %.12s; no earlier rebuild is recorded", err, target)
		}

		return fmt.Errorf("%w\nVERIFY FAILED after rebuilding %.12s; rebuild the last good commit: sbx rebuild %s", err, target, st.RebuiltSHA)
	}

	st.Name, st.Clone, st.RebuiltSHA, st.Image = a.name, clone, target, tag

	if _, err := a.saveState(st); err != nil {
		return err
	}

	fmt.Fprintf(a.out, "rebuilt %.12s (%s)\n", target, tag)

	return nil
}

// specAt parses config/sandbox.toml as of commit sha.
func (a *app) specAt(ctx context.Context, clone, sha string) (*config.Config, error) {
	raw, err := a.git(ctx, clone, "show", sha+":"+specPath).Output()
	if err != nil {
		return nil, fmt.Errorf("git show %.12s:%s: %w", sha, specPath, err)
	}

	return config.Parse(raw)
}

// showChanges prints the allowed hosts, addresses and secret bindings added or removed since the recorded commit, all of them if
// its config can't be read, and reports whether there were any.
func (a *app) showChanges(ctx context.Context, clone, recorded string, target *config.Config) bool {
	var old *config.Config

	since := "no earlier rebuild is recorded"

	if recorded != "" {
		cfg, err := a.specAt(ctx, clone, recorded)
		if err != nil {
			since = fmt.Sprintf("the config of %.12s can't be read: %v", recorded, err)
		} else {
			old, since = cfg, fmt.Sprintf("since %.12s", recorded)
		}
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
		out = append(out, fmt.Sprintf("secret %q hosts %q header_fields %q", s.Name, s.Allow, s.HeaderFields))
	}

	return out
}
