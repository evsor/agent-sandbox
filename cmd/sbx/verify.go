// The verify command: proves the running sandbox meets the baseline, black-box: guest checks, the live policy check and host checks.

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	msb "github.com/superradcompany/microsandbox/sdk/go"

	"github.com/spf13/cobra"

	"github.com/evsor/agent-sandbox/internal/policy"
	"github.com/evsor/agent-sandbox/internal/policy/claude"
)

var errVerify = errors.New("verify failed")

// rootDiskMiB is the root disk size verify requires, whatever the spec says, so a smaller spec fails.
const rootDiskMiB = 16384

// check is one row of the table: run returns nil for PASS, or why it failed. A FAIL in a boundary check stops the sandbox.
type check struct {
	name     string
	boundary bool
	run      func() error
}

func newVerifyCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Check that the running sandbox meets the baseline. Failed check stops it.",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.verify(cmd.Context())
		},
	}
}

func (a *app) verify(ctx context.Context) error {
	if a.name == "" {
		return errors.New("no sandbox recorded: run sbx init")
	}

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

	node := nodeExec(func(cmd string, args ...string) (*msb.ExecOutput, error) {
		return guest(ctx, sb, "node", cmd, args...)
	})

	return []check{
		{"guest: uid 1000, NoNewPrivs 1", true, func() error { return checkStatus(node) }},
		{"guest: " + claude.ManagedDir + " root-owned, readable and not writable by node", false, func() error { return checkManagedDir(node) }},
		{"guest: managed settings load", false, func() error { return checkManagedLoad(node) }},
		{"guest: no agent credential in env", false, func() error { return checkEnv(node) }},
		{"guest: volumes ext4, nosuid, nodev", true, func() error { return checkVolumes(node, live.Mounts) }},
		{"guest: volumes writable by node", false, func() error { return checkWritable(node, live.Mounts) }},
		{"guest: root disk about 16 GiB", false, func() error { return checkRootDisk(node) }},
		{"live policy check", true, func() error {
			if liveErr != nil {
				return liveErr
			}

			return policy.Check(live)
		}},
		{"host: sandbox directory 0700", false, a.checkSandboxDir},
		{"host: volume disk.raw 0600", false, func() error { return checkDiskModes(ctx, live.Mounts) }},
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

// nodeExec runs one argv command in the guest as node, in its home.
type nodeExec func(cmd string, args ...string) (*msb.ExecOutput, error)

// stdout returns the output of a command that must exit 0.
func (node nodeExec) stdout(cmd string, args ...string) (string, error) {
	out, err := node(cmd, args...)
	if err != nil {
		return "", err
	}

	if !out.Success() {
		return "", fmt.Errorf("%s exited %d: %q", cmd, out.ExitCode(), strings.TrimSpace(out.Stderr()))
	}

	return out.Stdout(), nil
}

func checkStatus(node nodeExec) error {
	status, err := node.stdout("cat", "/proc/self/status")
	if err != nil {
		return err
	}

	fields := map[string]string{}

	for line := range strings.Lines(status) {
		key, value, _ := strings.Cut(line, ":")
		fields[key] = strings.TrimSpace(value)
	}

	// Real, effective, saved and filesystem uid.
	if uids := strings.Fields(fields["Uid"]); len(uids) != 4 || slices.ContainsFunc(uids, func(id string) bool { return id != "1000" }) {
		return fmt.Errorf("uid is %q", fields["Uid"])
	}

	if fields["NoNewPrivs"] != "1" {
		return fmt.Errorf("NoNewPrivs is %q", fields["NoNewPrivs"])
	}

	return nil
}

// checkManagedDir also lists what node can't read: a forced login in node's own settings would hide that from checkManagedLoad.
func checkManagedDir(node nodeExec) error {
	listing, err := node.stdout("find", claude.ManagedDir, "(", "!", "-user", "root", "-o", "-writable", "-o", "!", "-readable", ")", "-print")
	if err != nil {
		return err
	}

	return claude.CheckManagedListing(listing)
}

// checkManagedLoad judges the output whatever the exit status: `claude auth status` exits 1 when not logged in.
func checkManagedLoad(node nodeExec) error {
	out, err := node("claude", "auth", "status", "--json")
	if err != nil {
		return err
	}

	return claude.CheckManagedLoad(out.StdoutBytes(), out.StderrBytes())
}

func checkEnv(node nodeExec) error {
	env, err := node.stdout("env")
	if err != nil {
		return err
	}

	return claude.CheckEnv(env)
}

func checkVolumes(node nodeExec, mounts []policy.Mount) error {
	table, err := node.stdout("cat", "/proc/mounts")
	if err != nil {
		return err
	}

	return eachMount(mounts, func(m policy.Mount) error {
		mounted := false

		for line := range strings.Lines(table) {
			f := strings.Fields(line)
			if len(f) < 4 || f[1] != m.Target {
				continue
			}

			mounted = true

			opts := strings.Split(f[3], ",")
			if f[2] != "ext4" || !slices.Contains(opts, "nosuid") || !slices.Contains(opts, "nodev") {
				return fmt.Errorf("%s is %q %q", m.Target, f[2], f[3])
			}
		}

		if !mounted {
			return fmt.Errorf("%s is not mounted", m.Target)
		}

		return nil
	})
}

func checkWritable(node nodeExec, mounts []policy.Mount) error {
	args := make([]string, 0, len(mounts)+4)
	for _, m := range mounts {
		args = append(args, m.Target)
	}

	listing, err := node.stdout("find", append(args, "-maxdepth", "0", "-writable", "-print")...)
	if err != nil {
		return err
	}

	writable := strings.Fields(listing)

	return eachMount(mounts, func(m policy.Mount) error {
		if !slices.Contains(writable, m.Target) {
			return fmt.Errorf("%s is not writable by node", m.Target)
		}

		return nil
	})
}

func checkRootDisk(node nodeExec) error {
	df, err := node.stdout("df", "--block-size=1", "--output=size", "/")
	if err != nil {
		return err
	}

	f := strings.Fields(df)
	if len(f) != 2 {
		return fmt.Errorf("df printed %q", df)
	}

	size, err := strconv.ParseUint(f[1], 10, 64)
	if err != nil {
		return fmt.Errorf("df printed %q: %w", df, err)
	}

	want := uint64(rootDiskMiB) << 20

	// The filesystem is a little smaller than its disk.
	if size < want*9/10 || size > want {
		return fmt.Errorf("%d MiB, want about %d MiB", size>>20, rootDiskMiB)
	}

	return nil
}

func (a *app) checkSandboxDir() error {
	home := os.Getenv("MSB_HOME")
	if home == "" {
		userHome, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("finding the home directory: %w", err)
		}

		home = filepath.Join(userHome, ".microsandbox")
	}

	return checkMode(filepath.Join(home, "sandboxes", a.name), 0o700)
}

func checkDiskModes(ctx context.Context, mounts []policy.Mount) error {
	return eachMount(mounts, func(m policy.Mount) error {
		v, err := msb.GetVolume(ctx, m.Name)
		if err != nil {
			return fmt.Errorf("finding volume %s: %w", m.Name, err)
		}

		return checkMode(filepath.Join(v.Path(), "disk.raw"), 0o600)
	})
}

func checkMode(path string, want os.FileMode) error {
	info, err := os.Stat(path) //nolint:gosec // msb's own sandbox and volume paths
	if err != nil {
		return fmt.Errorf("reading the mode: %w", err)
	}

	if info.Mode().Perm() != want {
		return fmt.Errorf("%s is %o, want %o", path, info.Mode().Perm(), want)
	}

	return nil
}

// eachMount runs fn on every mount. No mounts at all is a FAIL: nothing was checked.
func eachMount(mounts []policy.Mount, fn func(policy.Mount) error) error {
	if len(mounts) == 0 {
		return errors.New("the live config names no volumes")
	}

	var errs []error
	for _, m := range mounts {
		errs = append(errs, fn(m))
	}

	return errors.Join(errs...)
}
