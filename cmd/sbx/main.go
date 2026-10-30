// Sbx manages the local sandbox: a microsandbox microVM, built from the config/ directory of the agent-sandbox checkout, in which
// Claude Code runs.
//
// Usage:
//
//	sbx [flags] <command>
//
// Run sbx init from the agent-sandbox checkout. It checks the host, builds the image from config/, runs the policy check on the spec
// and the image, and creates and starts the sandbox; re-running it changes nothing. sbx --help lists the commands and flags.
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
	err := rootCmd().ExecuteContext(ctx)

	stop()

	if err != nil {
		fmt.Fprintln(os.Stderr, "sbx:", err)

		if errors.Is(err, errUsage) {
			os.Exit(2)
		}

		os.Exit(1)
	}
}
