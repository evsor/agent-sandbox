// The clone command: clones GitHub repos into the sandbox's /workspace, through the read-only token.

package main

import (
	"context"
	"errors"
	"fmt"
	"path"

	msb "github.com/superradcompany/microsandbox/sdk/go"

	"github.com/spf13/cobra"

	"github.com/evsor/agent-sandbox/internal/policy"
)

func newCloneCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "clone [<owner/name>...]",
		Short: "Clone GitHub repos into /workspace (default: origin of the checkout here)",
		Args:  cloneArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			repos := args
			if len(repos) == 0 {
				repo, err := a.originRepo(cmd.Context())
				if err != nil {
					return fmt.Errorf("%w: %w: pass owner/name", errUsage, err)
				}

				repos = []string{repo}
				if err := cloneArgs(cmd, repos); err != nil {
					return err
				}
			}

			return a.clone(cmd.Context(), repos)
		},
	}
}

// cloneArgs refuses the whole call as a usage error, so sbx exits 2, if any repo isn't owner/name, its name can't be a directory in
// /workspace, or two repos share a name.
func cloneArgs(_ *cobra.Command, repos []string) error {
	var errs []error

	seen := map[string]bool{}

	for _, repo := range repos {
		if err := policy.CheckGitHubRepo(repo); err != nil {
			errs = append(errs, err)

			continue
		}

		name := path.Base(repo)
		if err := policy.CheckRepoName(name); err != nil {
			errs = append(errs, err)
		}

		if seen[name] {
			errs = append(errs, fmt.Errorf("two repos named %q would clone into the same directory", name))
		}

		seen[name] = true
	}

	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}

	return nil
}

// originRepo reads owner/name from origin of the host checkout in the current directory.
func (a *app) originRepo(ctx context.Context) (string, error) {
	url, err := a.gitOut(ctx, ".", "remote", "get-url", "origin")
	if err != nil {
		return "", err
	}

	repo, err := policy.ParseGitHubURL(url)
	if err != nil {
		return "", fmt.Errorf("origin: %w", err)
	}

	return repo, nil
}

// clone starts the sandbox and clones each repo that isn't in /workspace yet, printing one line per repo. A failed repo doesn't stop
// the others.
func (a *app) clone(ctx context.Context, repos []string) error {
	sb, err := a.startSandbox(ctx)
	if err != nil {
		return err
	}

	defer release(ctx, sb)

	failed := 0

	for _, repo := range repos {
		dir := path.Join("/workspace", path.Base(repo))

		result, err := cloneRepo(ctx, sb, repo, dir)
		if err != nil {
			failed++

			fmt.Fprintf(a.out, "%-13s %s: %v\n", "failed", dir, err)

			continue
		}

		fmt.Fprintf(a.out, "%-13s %s\n", result, dir)
	}

	if failed > 0 {
		return fmt.Errorf("%d of %d repos failed", failed, len(repos))
	}

	return nil
}

// cloneRepo clones repo into dir as node, through the image's credential helper. An existing checkout is left untouched.
func cloneRepo(ctx context.Context, sb *msb.Sandbox, repo, dir string) (string, error) {
	exists, err := sb.FS().Exists(ctx, dir)
	if err != nil {
		return "", fmt.Errorf("checking %s: %w", dir, err)
	}

	if exists {
		checkout, err := sb.FS().Exists(ctx, path.Join(dir, ".git"))
		if err != nil {
			return "", fmt.Errorf("checking %s: %w", dir, err)
		}

		if !checkout {
			return "", errors.New("exists but is not a git checkout")
		}

		return "already there", nil
	}

	if _, err := guestStdout(ctx, sb, policy.NodeUser, "git", "clone", "--", "https://github.com/"+repo+".git", dir); err != nil {
		// GitHub answers a read of a private repo outside the token's list with "Write access to repository not granted".
		return "", fmt.Errorf("%w (a private repo must be on the read-only GitHub token's repository list)", err)
	}

	return "cloned", nil
}
