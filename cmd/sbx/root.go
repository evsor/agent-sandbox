// The root command: sbx

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	msb "github.com/superradcompany/microsandbox/sdk/go"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/evsor/agent-sandbox/internal/config"
)

// version is set at build time: -ldflags "-X main.version=dev-<short sha>" locally, X.Y.Z for releases.
var version = "dev"

var errUsage = errors.New("usage")

// app holds sbx's settings.
type app struct {
	v        *viper.Viper
	name     string
	nameSet  bool // --name or SBX_NAME given
	stateDir string
	out      io.Writer
}

func rootCmd() *cobra.Command {
	a := &app{v: viper.New()}

	root := &cobra.Command{
		Use:           "sbx",
		Short:         "Manage the local sandbox provisioned via microsandbox",
		Version:       version,
		Args:          noArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return a.setup(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return fmt.Errorf("%w: %w", errUsage, err)
	})

	flags := root.PersistentFlags()
	flags.String("name", "", "sandbox name (default: config/sandbox.toml's for init, the one init recorded otherwise)")
	flags.String("state-dir", "", "state directory (default ~/.local/state/agent-sandbox)")
	flags.String("log-level", "info", "log level: debug, info, warn or error")

	for _, key := range []string{"name", "state-dir", "log-level"} {
		if err := a.v.BindPFlag(key, flags.Lookup(key)); err != nil {
			panic(err)
		}
	}

	a.v.SetEnvPrefix("SBX")
	a.v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	a.v.AutomaticEnv()

	root.AddCommand(newInitCmd(a), newStatusCmd(a))

	return root
}

func noArgs(cmd *cobra.Command, args []string) error {
	if err := cobra.NoArgs(cmd, args); err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}

	return nil
}

func (a *app) setup(cmd *cobra.Command) error {
	var level slog.Level
	if err := level.UnmarshalText([]byte(a.v.GetString("log-level"))); err != nil {
		return fmt.Errorf("%w: --log-level: %w", errUsage, err)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	a.out = cmd.OutOrStdout()

	a.stateDir = a.v.GetString("state-dir")
	if a.stateDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("finding the home directory: %w", err)
		}

		a.stateDir = filepath.Join(home, ".local", "state", "agent-sandbox")
	}

	if err := os.MkdirAll(a.stateDir, 0o700); err != nil {
		return fmt.Errorf("creating the state directory: %w", err)
	}

	if err := checkRuntime(cmd.Context()); err != nil {
		return err
	}

	st, err := a.loadState()
	if err != nil {
		return err
	}

	a.name = a.v.GetString("name")
	a.nameSet = a.name != ""

	if !a.nameSet {
		a.name = st.Name
	}

	if a.name != "" && !config.ValidName(a.name) {
		return fmt.Errorf("%w: sandbox name %q: want lowercase letters, digits and dashes", errUsage, a.name)
	}

	return nil
}

// useSpecName takes the sandbox name from sandbox.toml unless --name or SBX_NAME is set.
func (a *app) useSpecName(s *spec) {
	if !a.nameSet {
		a.name = s.cfg.Name
	}
}

// Check msb's runtime and version compatibility with the SDK.
func checkRuntime(ctx context.Context) error {
	if os.Getenv("MSB_PATH") == "" {
		path, err := exec.LookPath("msb")
		if err != nil {
			return fmt.Errorf("msb not found in PATH: %w", err)
		}

		if err := os.Setenv("MSB_PATH", path); err != nil {
			return fmt.Errorf("setting MSB_PATH: %w", err)
		}
	}

	rt, err := msb.ResolveRuntime(msb.RuntimeConfig{})
	if err != nil {
		return fmt.Errorf("resolving the msb runtime: %w", err)
	}

	cmd := exec.CommandContext(ctx, rt.MSBPath, "--version") //nolint:gosec // the resolved msb binary
	cmd.Env = []string{}

	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("running %s --version: %w", rt.MSBPath, err)
	}

	got := strings.TrimPrefix(strings.TrimSpace(string(out)), "msb ")
	if got != msb.SDKVersion() {
		return fmt.Errorf("msb is %s but sbx's SDK is %s: update them together", got, msb.SDKVersion())
	}

	slog.Debug("runtime", "msb", rt.MSBPath, "version", got)

	return nil
}
