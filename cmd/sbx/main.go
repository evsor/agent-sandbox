// Sbx manages the local sandbox: a microsandbox microVM, built from the user config dir (default ~/.config/agent-sandbox), in which
// Claude Code runs.
//
// Usage:
//
//	sbx [flags] <command>
//
// Run sbx init first. It writes the example config, embedded in sbx, into the user config dir where a file is missing, checks the
// host, builds the image from that dir, runs the policy check on the spec and the image, creates and starts the sandbox, and verifies
// it. Re-running it creates nothing that already exists, but a failed boundary check in the verify step stops the sandbox. To change
// the sandbox, edit the user config dir and run sbx rebuild. sbx --help lists the commands and flags.
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
