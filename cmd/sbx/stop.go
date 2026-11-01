// The stop command: stops the sandbox

package main

import (
	"context"
	"fmt"

	msb "github.com/superradcompany/microsandbox/sdk/go"

	"github.com/spf13/cobra"
)

func newStopCmd(a *app) *cobra.Command {
	return newCmd("stop", "Stops the sandbox", a.stop)
}

func (a *app) stop(ctx context.Context) error {
	h, err := a.handle(ctx)
	if err != nil {
		return err
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
