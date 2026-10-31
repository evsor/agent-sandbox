// The connect command: the ssh ProxyCommand, which starts the sandbox if it's stopped and serves one SSH connection on stdin/stdout.

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	msb "github.com/superradcompany/microsandbox/sdk/go"

	"github.com/spf13/cobra"

	"github.com/evsor/agent-sandbox/internal/ssh"
)

const connectLong = `Serves one SSH connection on stdin/stdout, starting the sandbox detached if it's stopped.

ssh runs this for you; it is not a shell. sbx init writes the ssh config that sets it as the ProxyCommand
(shown with the default state dir and sandbox name):

  ssh -F ~/.local/state/agent-sandbox/ssh/config claude-sandbox

or, after adding "Include ~/.local/state/agent-sandbox/ssh/config" at the top of ~/.ssh/config,
"ssh claude-sandbox" and VS Code Remote-SSH. The sandbox keeps running after the connection closes.`

func newConnectCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "connect",
		Short: "The ssh ProxyCommand: ssh and VS Code run this; you don't",
		Long:  connectLong,
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.connect(cmd.Context())
		},
	}
}

// connect serves one SSH connection. stdout is the SSH transport, so nothing else may write to it.
func (a *app) connect(ctx context.Context) error {
	if a.name == "" {
		return errors.New("no sandbox recorded: run sbx init")
	}

	dir := ssh.Dir(a.stateDir)

	// Run by hand, it would wait forever for an SSH client.
	if info, err := os.Stdin.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
		return fmt.Errorf("%w: sbx connect is the ssh ProxyCommand, not a shell; run: ssh -F %s %s",
			errUsage, filepath.Join(dir, ssh.Config), a.name)
	}

	sb, err := a.startSandbox(ctx)
	if err != nil {
		return err
	}

	defer release(ctx, sb)

	srv, err := sb.SSH().PrepareServer(ctx,
		msb.WithSSHHostKeyPath(filepath.Join(dir, ssh.HostKey)),
		msb.WithSSHAuthorizedKeysPath(filepath.Join(dir, ssh.AuthorizedKeys)),
		msb.WithSSHServerUser("node"), // every login lands as node, whatever user the client asks for
	)
	if err != nil {
		return fmt.Errorf("preparing the SSH server: %w", err)
	}

	defer func() { _ = srv.Close(context.WithoutCancel(ctx)) }()

	if err := srv.ServeConnection(ctx); err != nil {
		return fmt.Errorf("serving SSH: %w", err)
	}

	return nil
}
