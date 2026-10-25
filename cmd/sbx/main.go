// Command sbx creates, connects to, ships from and rebuilds a microVM sandbox for Claude Code.
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
	// msb's logs, sandbox directories and volumes inherit this process's umask; its logs copy session output.
	syscall.Umask(0o077)

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
