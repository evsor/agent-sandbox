// The verify command: proves the running sandbox meets the baseline, black-box: guest checks, the live policy check and host checks.

package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	msb "github.com/superradcompany/microsandbox/sdk/go"

	"github.com/spf13/cobra"

	agent "github.com/evsor/agent-sandbox/internal/agent/claude"
	"github.com/evsor/agent-sandbox/internal/hostfs"
	"github.com/evsor/agent-sandbox/internal/policy"
	"github.com/evsor/agent-sandbox/internal/policy/claude"
)

var errVerify = errors.New("verify failed")

const (
	// allowedHost is an allowlisted host that needs no credential.
	allowedHost = "registry.npmjs.org"
	// githubSecret is the secret whose placeholder GH_TOKEN holds.
	githubSecret = "GITHUB_PAT"
)

// check is one row of the table: run returns nil for PASS, or why it failed. A FAIL in a boundary check stops the sandbox.
type check struct {
	name     string
	boundary bool
	run      func() error
}

func newVerifyCmd(a *app) *cobra.Command {
	return newCmd("verify", "Check that the running sandbox meets the baseline. Failed check stops it.", a.verify)
}

func (a *app) verify(ctx context.Context) error {
	sb, h, err := a.runningSandbox(ctx)
	if err != nil {
		return err
	}

	checks := a.checks(ctx, sb, h)
	failed, boundary := a.runChecks(checks)

	release(ctx, sb)

	// A check cut short by Ctrl-C proves nothing, so it stops nothing.
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("verify interrupted: %w", err)
	}

	if boundary {
		if err := h.Stop(ctx); err != nil {
			return fmt.Errorf("%w: a boundary check failed, but stopping %s failed too: %w", errVerify, a.name, err)
		}

		fmt.Fprintf(a.out, "A boundary check failed: %s is stopped\n", a.name)
	}

	if failed > 0 {
		return fmt.Errorf("%w: %d of %d checks", errVerify, failed, len(checks))
	}

	return nil
}

// checks builds the table. A live config that can't be read fails the live policy check, which can still stop the sandbox.
func (a *app) checks(ctx context.Context, sb *msb.Sandbox, h *msb.SandboxHandle) []check {
	live, liveErr := liveSpec(ctx, h)

	// checkOutput runs one argv command as node, which must exit 0, and passes its output to validate.
	checkOutput := func(validate func(string) error, cmd string, args ...string) func() error {
		return func() error {
			out, err := guestStdout(ctx, sb, policy.NodeUser, cmd, args...)
			if err != nil {
				return err
			}

			return validate(out)
		}
	}

	onMounts := func(validate func(string, []policy.Mount) error) func(string) error {
		return func(out string) error { return validate(out, live.Mounts) }
	}

	// blocked runs a curl that the network must refuse. curl exits non-zero then, so its exit status is part of the check.
	blocked := func(url string, extra ...string) func() error {
		return func() error {
			out, err := guest(ctx, sb, policy.NodeUser, "curl", policy.ProbeArgs(url, extra...)...)
			if err != nil {
				return err
			}

			return policy.CheckBlocked(out.ExitCode(), out.Stdout())
		}
	}

	allowedURL := "https://" + allowedHost + "/"

	return []check{
		{"guest: uid 1000, NoNewPrivs 1", true, checkOutput(policy.CheckProcStatus, "cat", "/proc/self/status")},
		// This also lists what node can't read: a forced login in node's own settings would hide that from the next check.
		{"guest: " + claude.ManagedDir + " root-owned, readable and not writable by node", false, checkOutput(claude.CheckManagedListing,
			"find", claude.ManagedDir, "(", "!", "-user", rootUser, "-o", "-writable", "-o", "!", "-readable", ")", "-print")},
		{"guest: managed settings load", false, func() error { return checkManagedLoad(ctx, sb) }},
		{"guest: no agent credential in env", false, checkOutput(claude.CheckEnv, "env")},
		{"guest: volumes ext4, nosuid, nodev", true, checkOutput(onMounts(policy.CheckProcMounts), "cat", "/proc/mounts")},
		{"guest: volumes writable by node", false, checkOutput(onMounts(policy.CheckWritable), "find", writableArgs(live.Mounts)...)},
		{"guest: root disk about 16 GiB", false, checkOutput(policy.CheckRootDisk, "df", policy.DFArgs("/")...)},
		{"live policy check", true, func() error {
			if liveErr != nil {
				return liveErr
			}

			return policy.Check(live)
		}},
		{"network: " + allowedHost + " answers over 443", false, checkOutput(policy.CheckAnswered, "curl", policy.ProbeArgs(allowedURL)...)},
		{"network: other host blocked", false, blocked("https://example.com/")},
		{"network: raw IP blocked", false, blocked("https://1.1.1.1/")},
		{"network: port 80 to an allowed host blocked", false, blocked("http://" + allowedHost + "/")},
		{"network: private address blocked", false, blocked("https://10.0.0.1/")},
		{"network: metadata address blocked", false, blocked("http://169.254.169.254/")},
		{"network: the host machine blocked", false, blocked("http://host.microsandbox.internal/")},
		{"network: domain fronting blocked", false, blocked(allowedURL, "-H", "Host: example.com")},
		{"network: unknown name does not resolve", false, func() error { return checkUnresolved(ctx, sb) }},
		{"auth: any login is the subscription", false, func() error { return checkLogin(ctx, sb) }},
		{"auth: GH_TOKEN is the " + githubSecret + " placeholder", false, checkOutput(func(out string) error {
			return policy.CheckIsPlaceholder(out, live.Secrets, githubSecret)
		}, "printenv", "GH_TOKEN")},
		{"auth: placeholder blocked on a host it isn't bound to", false, func() error {
			placeholder, err := policy.Placeholder(live.Secrets, githubSecret)
			if err != nil {
				return err
			}

			return blocked(allowedURL, "-H", "Authorization: token "+placeholder)()
		}},
		{"host: sandbox directory 0700", false, a.checkSandboxDir},
		{"host: volume disk.raw 0600", false, func() error { return checkDiskModes(ctx, live.Mounts) }},
		{"host: no secret value in a guest process environment", false, func() error { return a.checkSecretsAbsent(ctx, sb, live.Secrets) }},
	}
}

// runChecks prints a row per check and returns how many failed and whether a boundary check is among them.
func (a *app) runChecks(checks []check) (int, bool) {
	failed, boundary := 0, false

	for _, c := range checks {
		err := c.run()
		if err == nil {
			a.report("PASS", c.name)

			continue
		}

		failed++
		boundary = boundary || c.boundary

		a.report("FAIL", c.name+": "+strings.ReplaceAll(err.Error(), "\n", "; "))
	}

	return failed, boundary
}

// checkManagedLoad checks the output whatever the exit status: `claude auth status` exits 1 when not logged in.
func checkManagedLoad(ctx context.Context, sb *msb.Sandbox) error {
	out, err := guest(ctx, sb, policy.NodeUser, agent.Command, agent.AuthStatusArgs...)
	if err != nil {
		return err
	}

	return claude.CheckManagedLoad(out.StdoutBytes(), out.StderrBytes())
}

// checkLogin checks the output whatever the exit status: `claude auth status` exits 1 when not logged in.
func checkLogin(ctx context.Context, sb *msb.Sandbox) error {
	out, err := guest(ctx, sb, policy.NodeUser, agent.Command, agent.AuthStatusArgs...)
	if err != nil {
		return err
	}

	return claude.CheckLogin(out.StdoutBytes())
}

// checkUnresolved looks up a name nobody allowed, new on every run so no cache can answer. An allowlist resolves only its own names.
func checkUnresolved(ctx context.Context, sb *msb.Sandbox) error {
	out, err := guest(ctx, sb, policy.NodeUser, "getent", "hosts", "sbx-"+strings.ToLower(rand.Text())+".example.com")
	if err != nil {
		return err
	}

	return policy.CheckUnresolved(out.ExitCode(), out.Stdout())
}

// writableArgs are the arguments of a find that lists the mounts node can write.
func writableArgs(mounts []policy.Mount) []string {
	args := make([]string, 0, len(mounts)+4)
	for _, m := range mounts {
		args = append(args, m.Target)
	}

	return append(args, "-maxdepth", "0", "-writable", "-print")
}

func (a *app) checkSandboxDir() error {
	home := os.Getenv("MSB_HOME")
	if home == "" {
		var err error

		home, err = hostfs.HomePath(".microsandbox")
		if err != nil {
			return err
		}
	}

	return hostfs.CheckMode(filepath.Join(home, "sandboxes", a.name), 0o700)
}

func checkDiskModes(ctx context.Context, mounts []policy.Mount) error {
	return policy.EachMount(mounts, func(m policy.Mount) error {
		v, err := msb.GetVolume(ctx, m.Name)
		if err != nil {
			return fmt.Errorf("finding volume %s: %w", m.Name, err)
		}

		return hostfs.CheckMode(filepath.Join(v.Path(), "disk.raw"), 0o600)
	})
}

// checkSecretsAbsent reads every guest process's environment and looks for the values here on the host, so they never enter the guest.
func (a *app) checkSecretsAbsent(ctx context.Context, sb *msb.Sandbox, secrets []policy.Secret) error {
	// As root, to read every process. A process that exits mid-scan makes find exit non-zero, so its exit status says nothing.
	out, err := guest(ctx, sb, rootUser, "find", "/proc", "-mindepth", "2", "-maxdepth", "2", "-name", "environ", "-exec", "cat", "{}", "+")
	if err != nil {
		return err
	}

	return policy.CheckSecretsAbsent(out.StdoutBytes(), secrets, a.secret)
}
