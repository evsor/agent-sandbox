// The root command: sbx

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	msb "github.com/superradcompany/microsandbox/sdk/go"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	example "github.com/evsor/agent-sandbox/config"
	"github.com/evsor/agent-sandbox/internal/config"
	"github.com/evsor/agent-sandbox/internal/hostfs"
)

// version is set at build time: -ldflags "-X main.version=dev-<short sha>" locally, X.Y.Z for releases.
var version = "dev"

var errUsage = errors.New("usage")

// app holds sbx's settings.
type app struct {
	v         *viper.Viper
	name      string
	nameSet   bool // --name or SBX_NAME given
	stateDir  string
	configDir string            // the user config dir, absolute
	declared  []string          // secret variables, removed from sbx's environment and every child's
	secrets   map[string]string // their values, read once
	in        *bufio.Reader
	out       io.Writer
}

func rootCmd() *cobra.Command {
	a := &app{v: viper.New(), secrets: map[string]string{}}

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
	flags.String("name", "", "sandbox name (default: sandbox.toml in the config dir)")
	flags.String("state-dir", "", "state directory (default ~/.local/state/agent-sandbox)")
	flags.String("config-dir", "", "user config dir (default: the one sbx init recorded, else ~/.config/agent-sandbox)")
	flags.String("log-level", "info", "log level: debug, info, warn or error")

	for _, key := range []string{"name", "state-dir", "config-dir", "log-level"} {
		if err := a.v.BindPFlag(key, flags.Lookup(key)); err != nil {
			panic(err)
		}
	}

	a.v.SetEnvPrefix("SBX")
	a.v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	a.v.AutomaticEnv()

	root.AddCommand(newInitCmd(a), newStatusCmd(a), newStopCmd(a), newVerifyCmd(a), newConnectCmd(a), newRotateCmd(a), newShipCmd(a), newRebuildCmd(a), newCloneCmd(a))

	return root
}

// newCmd builds a subcommand that takes no arguments.
func newCmd(use, short string, run func(context.Context) error) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context())
		},
	}
}

// noArgs rejects arguments as a usage error, so sbx exits 2.
func noArgs(cmd *cobra.Command, args []string) error {
	if err := cobra.NoArgs(cmd, args); err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}

	return nil
}

// setup runs before every command: it sets the logger and the state directory, checks the msb runtime, settles the sandbox name and
// the config dir, and reads the secrets.
func (a *app) setup(cmd *cobra.Command) error {
	var level slog.Level
	if err := level.UnmarshalText([]byte(a.v.GetString("log-level"))); err != nil {
		return fmt.Errorf("%w: --log-level: %w", errUsage, err)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	a.in = bufio.NewReader(cmd.InOrStdin())
	a.out = cmd.OutOrStdout()

	a.stateDir = a.v.GetString("state-dir")
	if a.stateDir == "" {
		dir, err := hostfs.HomePath(".local", "state", "agent-sandbox")
		if err != nil {
			return err
		}

		a.stateDir = dir
	}

	if err := hostfs.EnsureDir(a.stateDir); err != nil {
		return err
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

	if err := a.setConfigDir(st); err != nil {
		return err
	}

	return a.declareKnown(cmd.Context())
}

// setConfigDir takes the user config dir from --config-dir or SBX_CONFIG_DIR, else the one init recorded, else the default.
func (a *app) setConfigDir(st state) error {
	dir := a.v.GetString("config-dir")
	if dir == "" {
		dir = st.ConfigDir
	}

	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return fmt.Errorf("finding the config directory: %w", err)
		}

		dir = filepath.Join(base, "agent-sandbox")
	}

	// It's recorded in state.json, for commands run from any directory.
	abs, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("finding the config directory: %w", err)
	}

	a.configDir = abs

	return nil
}

// declareKnown learns the secret names before sbx starts a child process: from the config dir's spec, the example's, which init
// writes into a dir without one, and the live sandbox.
func (a *app) declareKnown(ctx context.Context) error {
	// A missing or broken spec is for init and rebuild to report: the other commands don't need it.
	if s, err := loadSpec(a.configDir); err == nil {
		a.declare(s.cfg.SecretNames()...)
	}

	if raw, err := example.FS.ReadFile(config.SpecFile); err == nil {
		if cfg, err := config.Parse(raw); err == nil {
			a.declare(cfg.SecretNames()...)
		}
	}

	if a.name == "" {
		return nil
	}

	h, err := a.handle(ctx)
	if msb.IsKind(err, msb.ErrSandboxNotFound) {
		return nil
	}

	if err != nil {
		return err
	}

	live, err := liveSecrets(h)
	if err != nil {
		// Not fatal: verify must still run, to fail its live policy check and stop the sandbox.
		slog.Warn("reading the live secret names", "err", err)

		return nil
	}

	for _, s := range live {
		a.declare(s.Name)
	}

	return nil
}

// declare reads each secret's value once and removes it from sbx's environment, so no child inherits it, the msb runtime the SDK
// starts included.
func (a *app) declare(names ...string) {
	for _, name := range names {
		if slices.Contains(a.declared, name) {
			continue
		}

		a.declared = append(a.declared, name)

		if value, ok := os.LookupEnv(name); ok {
			a.secrets[name] = value

			if err := os.Unsetenv(name); err != nil {
				panic(err) // only an invalid name fails, and LookupEnv just found this one
			}
		}
	}
}

// secret returns a declared secret's value, read from the environment at start.
func (a *app) secret(name string) string {
	return a.secrets[name]
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
	cmd.Env = []string{}                                     // the secret names aren't known yet

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
