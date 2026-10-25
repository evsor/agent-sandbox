package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	m "github.com/superradcompany/microsandbox/sdk/go"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// version is set at build time: -ldflags "-X main.version=dev-<short sha>" locally, X.Y.Z for releases.
var version = "dev"

var errUsage = errors.New("usage")

func newRootCmd() *cobra.Command {
	v := viper.New()

	root := &cobra.Command{
		Use:     "sbx",
		Short:   "Create, connect to, ship from and rebuild the local sandbox",
		Version: version,
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.NoArgs(cmd, args); err != nil {
				return fmt.Errorf("%w: %w", errUsage, err)
			}

			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return setup(cmd.Context(), v)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return fmt.Errorf("%w: %w", errUsage, err)
	})

	flags := root.PersistentFlags()
	flags.String("log-level", "info", "log level: debug, info, warn or error")

	if err := v.BindPFlag("log-level", flags.Lookup("log-level")); err != nil {
		panic(err)
	}

	v.SetEnvPrefix("SBX")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()

	return root
}

func setup(ctx context.Context, v *viper.Viper) error {
	var level slog.Level
	if err := level.UnmarshalText([]byte(v.GetString("log-level"))); err != nil {
		return fmt.Errorf("%w: --log-level: %w", errUsage, err)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	return checkRuntime(ctx)
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

	rt, err := m.ResolveRuntime(m.RuntimeConfig{})
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
	if got != m.SDKVersion() {
		return fmt.Errorf("msb is %s but sbx's SDK is %s: update them together", got, m.SDKVersion())
	}

	slog.Debug("runtime", "msb", rt.MSBPath, "version", got)

	return nil
}
