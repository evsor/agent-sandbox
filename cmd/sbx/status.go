// The status command: reports on the sandbox

package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	msb "github.com/superradcompany/microsandbox/sdk/go"

	"github.com/spf13/cobra"

	agent "github.com/evsor/agent-sandbox/internal/agent/claude"
	"github.com/evsor/agent-sandbox/internal/policy"
)

func newStatusCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the sandbox's state, image, pending rebuild, volume usage, login and background sessions",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.status(cmd.Context())
		},
	}
}

func (a *app) status(ctx context.Context) error {
	if a.name == "" {
		fmt.Fprintln(a.out, "sandbox  not created (run sbx init)")

		return nil
	}

	h, err := msb.GetSandbox(ctx, a.name)
	if msb.IsKind(err, msb.ErrSandboxNotFound) {
		fmt.Fprintf(a.out, "sandbox  %s: not created (run sbx init)\n", a.name)

		return nil
	}

	if err != nil {
		return fmt.Errorf("finding sandbox %s: %w", a.name, err)
	}

	live, err := liveSpec(ctx, h)
	if err != nil {
		return err
	}

	fmt.Fprintf(a.out, "sandbox  %s: %s\nimage    %s\n", a.name, h.Status(), live.Image)

	if err := a.pendingRebuild(ctx); err != nil {
		return err
	}

	sb, _, err := a.runningSandbox(ctx)
	if errors.Is(err, errNotRunning) {
		return nil
	}

	if err != nil {
		return err
	}

	defer release(ctx, sb)

	for _, mount := range live.Mounts {
		if err := a.volumeUsage(ctx, sb, mount); err != nil {
			return err
		}
	}

	if err := a.loginStatus(ctx, sb); err != nil {
		return err
	}

	sessions, err := backgroundSessions(ctx, sb)
	if err != nil {
		return err
	}

	fmt.Fprintf(a.out, "agents   %d background session(s)\n", len(sessions))

	for _, s := range sessions {
		fmt.Fprintf(a.out, "         %q  %q  %q  %q\n", s.ID, s.State, s.Name, s.Cwd)
	}

	return nil
}

// pendingRebuild compares the last rebuilt commit with origin/main as of the clone's last fetch.
func (a *app) pendingRebuild(ctx context.Context) error {
	st, err := a.loadState()
	if err != nil {
		return err
	}

	if st.RebuiltSHA == "" {
		fmt.Fprintln(a.out, "rebuild  never rebuilt")

		return nil
	}

	head, err := gitOut(ctx, st.Clone, "rev-parse", "origin/main")
	if err != nil {
		// A clone that moved shouldn't hide the rest of the report.
		fmt.Fprintf(a.out, "rebuild  unknown: %v\n", err)

		return nil
	}

	if st.RebuiltSHA == head {
		fmt.Fprintf(a.out, "rebuild  up to date (%.12s)\n", head)
	} else {
		fmt.Fprintf(a.out, "rebuild  pending (run sbx rebuild): at %.12s, origin/main is %.12s\n", st.RebuiltSHA, head)
	}

	return nil
}

// volumeUsage reads usage with df in the guest: the SDK reports 0 for disk volumes.
func (a *app) volumeUsage(ctx context.Context, sb *msb.Sandbox, mount policy.Mount) error {
	out, err := guest(ctx, sb, "node", "df", "--block-size=1", "--output=used,size", mount.Target)
	if err != nil {
		return err
	}

	f := strings.Fields(out.Stdout())
	if len(f) != 4 {
		return fmt.Errorf("df %s: %q", mount.Target, out.Stdout())
	}

	used, err1 := strconv.ParseUint(f[2], 10, 64)
	size, err2 := strconv.ParseUint(f[3], 10, 64)

	if err := errors.Join(err1, err2); err != nil || size == 0 {
		return fmt.Errorf("df %s: %q", mount.Target, out.Stdout())
	}

	pct := used * 100 / size

	warn := ""
	if pct >= 80 {
		warn = "  WARNING: 80% or more used (disk volumes can't grow)"
	}

	fmt.Fprintf(a.out, "volume   %s: %.1f of %.1f GiB (%d%%)%s\n", mount.Name, float64(used)/(1<<30), float64(size)/(1<<30), pct, warn)

	return nil
}

// loginStatus reads the login from stdout whatever the exit status: `claude auth status` exits 1 when not logged in.
func (a *app) loginStatus(ctx context.Context, sb *msb.Sandbox) error {
	out, err := guest(ctx, sb, "node", "claude", "auth", "status", "--json")
	if err != nil {
		return err
	}

	login, err := agent.ParseLogin(out.StdoutBytes())
	if err != nil {
		return err
	}

	if login.LoggedIn {
		fmt.Fprintf(a.out, "login    logged in (%q)\n", login.Method)
	} else {
		fmt.Fprintln(a.out, "login    not logged in (run /login in the sandbox)")
	}

	return nil
}
