// The stop command: stops the sandbox

package main

import (
	"context"
	"errors"
	"fmt"

	msb "github.com/superradcompany/microsandbox/sdk/go"

	"github.com/spf13/cobra"
)

func newStopCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stops the sandbox",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.stop(cmd.Context())
		},
	}
}

func (a *app) stop(ctx context.Context) error {
	if a.name == "" {
		return errors.New("no sandbox recorded: run sbx init")
	}

	h, err := msb.GetSandbox(ctx, a.name)
	if err != nil {
		return fmt.Errorf("finding sandbox %s: %w", a.name, err)
	}

	if h.Status() == msb.SandboxStatusStopped {
		fmt.Fprintf(a.out, "%s is already stopped\n", a.name)

		return nil
	}

	if err := h.Stop(ctx); err != nil {
		return fmt.Errorf("stopping %s: %w", a.name, err)
	}

	fmt.Fprintf(a.out, "%s stopped\n", a.name)

	return nil
}
