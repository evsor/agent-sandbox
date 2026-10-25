// sbx is the main entry point for the agent-sandbox CLI
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// Created files and directories should be accessible only by the owner
	syscall.Umask(0o077)

	// Intercept Ctrl+C and termination signals to gracefully shut down the CLI
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := newRootCmd().ExecuteContext(ctx)

	stop()

	if err != nil {
		fmt.Fprintln(os.Stderr, "sbx:", err)

		if errors.Is(err, errUsage) {
			os.Exit(2)
		}

		os.Exit(1)
	}
}
