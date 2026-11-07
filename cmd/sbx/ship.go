// The ship command: moves an agent branch from the sandbox to GitHub and opens a PR, without checking out its code on the host.

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	msb "github.com/superradcompany/microsandbox/sdk/go"

	"github.com/spf13/cobra"

	"github.com/evsor/agent-sandbox/internal/hostfs"
	"github.com/evsor/agent-sandbox/internal/policy"
	"github.com/evsor/agent-sandbox/internal/ssh"
)

// candidate is a guest branch with commits that origin doesn't have.
type candidate struct {
	repo, branch string
	commits      int
}

func newShipCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "ship [<repo> [<branch>]]",
		Short: "Fetch an agent branch to the host, push it to GitHub and open a PR",
		Args:  shipArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.ship(cmd.Context(), args)
		},
	}
}

// shipArgs rejects extra arguments as a usage error, so sbx exits 2.
func shipArgs(cmd *cobra.Command, args []string) error {
	if err := cobra.MaximumNArgs(2)(cmd, args); err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}

	return nil
}

func (a *app) ship(ctx context.Context, args []string) error {
	if a.name == "" {
		return errNoSandbox
	}

	repo, branch, err := a.pickBranch(ctx, args)
	if err != nil {
		return err
	}

	// Names come from the guest: they must not escape the repos directory or look like options.
	if err := errors.Join(policy.CheckRepoName(repo), policy.CheckBranchName(branch)); err != nil {
		return err
	}

	if err := a.git(ctx, a.stateDir, "check-ref-format", "--branch", branch).Run(); err != nil {
		return fmt.Errorf("branch name %q: %w", branch, err)
	}

	target, err := a.pushTarget(repo)
	if err != nil {
		return err
	}

	bare, err := a.bareRepo(ctx, repo)
	if err != nil {
		return err
	}

	base, err := a.fetchBranch(ctx, bare, target, repo, branch)
	if err != nil {
		return err
	}

	if !a.ask(fmt.Sprintf("Push %q to github.com/%s and open a PR?", branch, target)) {
		return errors.New("cancelled")
	}

	ref := "refs/heads/" + branch
	if err := a.git(ctx, bare, "push", githubURL(target), ref+":"+ref).Run(); err != nil {
		return fmt.Errorf("pushing %q: %w", branch, err)
	}

	if err := a.recordTarget(repo, target); err != nil {
		return err
	}

	pr := a.gh(ctx, "pr", "create", "-R", target, "--head", branch, "--base", base, "--fill")
	pr.Dir = bare // --fill reads the commits from here
	pr.Stdout = a.out

	if err := pr.Run(); err != nil {
		return fmt.Errorf("gh pr create: %w", err)
	}

	return nil
}

// pickBranch takes repo and branch from args, or lists the guest branches with unshipped commits and asks for one.
func (a *app) pickBranch(ctx context.Context, args []string) (string, string, error) {
	if len(args) == 2 {
		return args[0], args[1], nil
	}

	sb, err := a.startSandbox(ctx)
	if err != nil {
		return "", "", err
	}

	defer release(ctx, sb)

	only := ""
	if len(args) == 1 {
		only = args[0]
	}

	cands, err := listCandidates(ctx, sb, only)
	if err != nil {
		return "", "", err
	}

	if len(cands) == 0 {
		return "", "", errors.New("no branch in /workspace has commits that origin doesn't have")
	}

	for i, c := range cands {
		fmt.Fprintf(a.out, "%2d) %q %q (%d commits)\n", i+1, c.repo, c.branch, c.commits) // %q: guest strings
	}

	n, err := strconv.Atoi(a.prompt("Ship which? "))
	if err != nil || n < 1 || n > len(cands) {
		return "", "", errors.New("no branch picked")
	}

	return cands[n-1].repo, cands[n-1].branch, nil
}

// listCandidates finds the branches with commits that origin doesn't have. A repo or branch git can't read is skipped.
func listCandidates(ctx context.Context, sb *msb.Sandbox, only string) ([]candidate, error) {
	out, err := guest(ctx, sb, policy.NodeUser, "find", "/workspace", "-mindepth", "2", "-maxdepth", "2", "-name", ".git")
	if err != nil {
		return nil, err
	}

	var cands []candidate

	for line := range strings.Lines(out.Stdout()) {
		dir := path.Dir(strings.TrimSpace(line))

		repo := path.Base(dir)
		if only != "" && repo != only {
			continue
		}

		// lstrip, not short: short turns a branch into heads/<branch> when a tag has the same name.
		refs, err := guest(ctx, sb, policy.NodeUser, "git", "-C", dir, "for-each-ref", "--format=%(refname:lstrip=2)", "refs/heads")
		if err != nil {
			return nil, err
		}

		for branch := range strings.FieldsSeq(refs.Stdout()) {
			count, err := guest(ctx, sb, policy.NodeUser, "git", "-C", dir, "rev-list", "--count", "refs/heads/"+branch, "--not", "--remotes=origin")
			if err != nil {
				return nil, err
			}

			if n, err := policy.ParseCommitCount(count.Stdout()); err == nil && n > 0 {
				cands = append(cands, candidate{repo: repo, branch: branch, commits: n})
			}
		}
	}

	return cands, nil
}

// pushTarget returns the GitHub repo recorded for a guest repo, asking on its first ship. It never comes from the guest, so an agent
// can't redirect a push by editing origin.
func (a *app) pushTarget(repo string) (string, error) {
	st, err := a.loadState()
	if err != nil {
		return "", err
	}

	if target := st.Repos[repo]; target != "" {
		return target, nil
	}

	target := a.prompt(fmt.Sprintf("First ship of %s: which GitHub repo does it push to (owner/name)? ", repo))
	if err := policy.CheckGitHubRepo(target); err != nil {
		return "", err
	}

	return target, nil
}

// recordTarget stores the push target once a push has reached it, so a wrong first answer isn't kept.
func (a *app) recordTarget(repo, target string) error {
	st, err := a.loadState()
	if err != nil {
		return err
	}

	if st.Repos == nil {
		st.Repos = map[string]string{}
	}

	st.Repos[repo] = target

	_, err = a.saveState(st)

	return err
}

// bareRepo returns the host bare repo for a guest repo, creating it. A bare repo has no working tree, so no agent code lands on the host.
func (a *app) bareRepo(ctx context.Context, repo string) (string, error) {
	dir, err := hostfs.HomePath(".local", "share", "agent-sandbox", "repos")
	if err != nil {
		return "", err
	}

	bare := filepath.Join(dir, repo+".git")

	exists, err := hostfs.Exists(bare)
	if err != nil {
		return "", err
	}

	if exists {
		return bare, nil
	}

	if err := hostfs.EnsureDir(dir); err != nil {
		return "", err
	}

	if err := a.git(ctx, dir, "init", "--quiet", "--bare", bare).Run(); err != nil {
		return "", fmt.Errorf("creating %s: %w", bare, err)
	}

	return bare, nil
}

// fetchBranch fetches the GitHub default branch and the guest branch into the bare repo, shows the branch's log --stat and returns the
// default branch, which it refuses to ship.
func (a *app) fetchBranch(ctx context.Context, bare, target, repo, branch string) (string, error) {
	base, err := a.defaultBranch(ctx, target)
	if err != nil {
		return "", err
	}

	if branch == base {
		return "", fmt.Errorf("refusing to ship %s, the default branch: every change reaches it through a PR", branch)
	}

	// A local branch: gh pr create --fill compares against the base by its short name, and this repo has no remotes.
	baseRef := "refs/heads/" + base
	if err := a.git(ctx, bare, "fetch", "--no-tags", githubURL(target), "+"+baseRef+":"+baseRef).Run(); err != nil {
		return "", fmt.Errorf("fetching %s from GitHub: %w", base, err)
	}

	stateDir, err := filepath.Abs(a.stateDir)
	if err != nil {
		return "", fmt.Errorf("finding the state directory: %w", err)
	}

	// Through the ssh alias only git objects cross, and fsck checks them.
	ref := "refs/heads/" + branch
	fetch := a.git(ctx, bare, "fetch", "--no-tags", a.name+":"+path.Join("/workspace", repo), "+"+ref+":"+ref)
	fetch.Env = append(fetch.Env, "GIT_SSH_COMMAND=ssh -F '"+filepath.Join(ssh.Dir(stateDir), ssh.Config)+"'") // git runs it with sh

	if err := fetch.Run(); err != nil {
		return "", fmt.Errorf("fetching %q from the sandbox: %w", branch, err)
	}

	// Full refs, so no tag or branch with a similar name can change what the log shows.
	log := a.git(ctx, bare, "log", "--stat", baseRef+".."+ref)
	log.Stdout = a.out

	if err := log.Run(); err != nil {
		return "", fmt.Errorf("git log: %w", err)
	}

	return base, nil
}

// defaultBranch asks GitHub for the repo's default branch.
func (a *app) defaultBranch(ctx context.Context, target string) (string, error) {
	out, err := a.gh(ctx, "repo", "view", target, "--json", "defaultBranchRef", "--jq", ".defaultBranchRef.name").Output()
	if err != nil {
		return "", fmt.Errorf("gh repo view %s: %w", target, err)
	}

	base := strings.TrimSpace(string(out))
	if base == "" {
		return "", fmt.Errorf("%s has no default branch", target)
	}

	return base, nil
}

// gh runs gh with the user's login and an environment without GIT_* or the declared secrets, since gh runs git.
func (a *app) gh(ctx context.Context, args ...string) *exec.Cmd {
	cmd := a.command(ctx, "gh", args...)
	cmd.Env = scrubEnv(os.Environ(), a.declared, true)

	return cmd
}

// githubURL is the repo's address for git, reached with the user's own SSH key.
func githubURL(target string) string {
	return "git@github.com:" + target + ".git"
}
