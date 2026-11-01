// The rotate command: updates every secret from its host variable, live unless msb says it needs a restart.

package main

import (
	"context"
	"errors"
	"fmt"
	"slices"

	msb "github.com/superradcompany/microsandbox/sdk/go"

	"github.com/spf13/cobra"

	"github.com/evsor/agent-sandbox/internal/config"
	"github.com/evsor/agent-sandbox/internal/policy"
)

func newRotateCmd(a *app) *cobra.Command {
	return newCmd("rotate", "Update every secret from its host variable", a.rotate)
}

func (a *app) rotate(ctx context.Context) error {
	h, err := a.handle(ctx)
	if err != nil {
		return err
	}

	before, err := liveSecrets(h)
	if err != nil {
		return err
	}

	if len(before) == 0 {
		fmt.Fprintln(a.out, "no secrets declared")

		return nil
	}

	names := make([]string, 0, len(before))
	for _, s := range before {
		names = append(names, s.Name)
	}

	values, err := config.SecretValues(names, a.secret)
	if err != nil {
		return err
	}

	opts := msb.ModifyOptions{Secrets: map[string]msb.SecretModifySpec{}, Policy: msb.ModificationPolicyRestart}
	for name, value := range values {
		opts.Secrets[name] = msb.SecretModifySpec{Value: value}
	}

	if err := a.confirmRestart(ctx, h, opts); err != nil {
		return err
	}

	unlock, err := a.lock() // a restart starts the sandbox
	if err != nil {
		return err
	}

	plan, err := h.Modify(ctx, opts)

	unlock()

	if err != nil {
		return fmt.Errorf("rotating the secrets: %w", err)
	}

	for _, c := range plan.Changes {
		fmt.Fprintf(a.out, "%s %s (%s)\n", c.Change, c.Name, c.Disposition)
	}

	// The SDK can't set header_fields on a modify, so check that the rotation kept them.
	h, err = h.Refresh(ctx)
	if err != nil {
		return fmt.Errorf("re-reading sandbox %s: %w", a.name, err)
	}

	after, err := liveSecrets(h)
	if err != nil {
		return err
	}

	return sameSecrets(before, after)
}

// confirmRestart dry-runs the change and asks about background sessions only if it needs a restart.
func (a *app) confirmRestart(ctx context.Context, h *msb.SandboxHandle, opts msb.ModifyOptions) error {
	opts.DryRun = true

	plan, err := h.Modify(ctx, opts)
	if err != nil {
		return fmt.Errorf("planning the rotation: %w", err)
	}

	if len(plan.Conflicts) > 0 {
		return fmt.Errorf("rotation conflicts: %+v", plan.Conflicts)
	}

	for _, c := range plan.Changes {
		if c.Disposition != "live" {
			return a.confirmSessions(ctx, "Restarting the sandbox")
		}
	}

	return nil
}

// sameSecrets fails if a rotation changed what a secret is bound to.
func sameSecrets(before, after []policy.Secret) error {
	var errs []error

	for _, b := range before {
		i := slices.IndexFunc(after, func(s policy.Secret) bool { return s.Name == b.Name })

		switch {
		case i < 0:
			errs = append(errs, fmt.Errorf("secret %s disappeared", b.Name))
		case !slices.Equal(b.Hosts, after[i].Hosts):
			errs = append(errs, fmt.Errorf("secret %s: hosts changed to %v", b.Name, after[i].Hosts))
		case b.Placeholder != after[i].Placeholder:
			errs = append(errs, fmt.Errorf("secret %s: placeholder changed", b.Name))
		case !slices.Equal(b.HeaderFields, after[i].HeaderFields):
			errs = append(errs, fmt.Errorf("secret %s: header_fields changed to %v", b.Name, after[i].HeaderFields))
		}
	}

	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("THE ROTATION CHANGED THE SECRET POLICY, fix it with sbx rebuild: %w", err)
	}

	return nil
}
