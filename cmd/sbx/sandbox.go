// Sandbox management: the spec, the image, creating the sandbox, and reading a running one's config and background sessions.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	msb "github.com/superradcompany/microsandbox/sdk/go"

	agent "github.com/evsor/agent-sandbox/internal/agent/claude"
	"github.com/evsor/agent-sandbox/internal/config"
	"github.com/evsor/agent-sandbox/internal/policy"
	"github.com/evsor/agent-sandbox/internal/policy/claude"
)

const nodeHome = "/home/node"

var errNotRunning = errors.New("sandbox is not running")

// spec is the sandbox spec from config/sandbox.toml.
type spec struct {
	repo string
	cfg  *config.Config
	raw  []byte
}

func loadSpec(repo string) (*spec, error) {
	path := filepath.Join(repo, "config", "sandbox.toml")

	raw, err := os.ReadFile(path) //nolint:gosec // the spec of the checkout sbx runs from
	if err != nil {
		return nil, fmt.Errorf("reading the spec: %w", err)
	}

	cfg, err := config.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	return &spec{repo: repo, cfg: cfg, raw: raw}, nil
}

// check runs the policy check on the spec.
func (s *spec) check() error {
	return policy.Check(policy.FromConfig(s.cfg, s.raw))
}

// imageTag is the spec's image tagged with the checkout's short SHA.
func imageTag(ctx context.Context, s *spec) (string, error) {
	sha, err := gitOut(ctx, s.repo, "rev-parse", "--short", "HEAD")
	if err != nil {
		return "", err
	}

	return s.cfg.Image + ":" + sha, nil
}

// ensureImage builds the checkout's image with docker, checks it and loads it into msb.
func (a *app) ensureImage(ctx context.Context, s *spec, tag string) error {
	_, err := msb.Image.Get(ctx, tag)

	switch {
	case err == nil:
		a.report("ok", "image "+tag+" (msb has it)")

		return nil
	case !msb.IsKind(err, msb.ErrImageNotFound):
		return fmt.Errorf("finding image %s: %w", tag, err)
	}

	build := command(ctx, "docker", "build", "-t", tag, filepath.Join(s.repo, "config"))
	build.Stdout = os.Stderr

	if err := build.Run(); err != nil {
		return fmt.Errorf("docker build: %w", err)
	}

	if err := checkImage(ctx, tag); err != nil {
		return err
	}

	a.report("ok", "policy check: image "+tag)

	tmp, err := os.MkdirTemp("", "sbx-image-")
	if err != nil {
		return fmt.Errorf("creating a temporary directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	tar := filepath.Join(tmp, "image.tar")
	if err := command(ctx, "docker", "save", "-o", tar, tag).Run(); err != nil {
		return fmt.Errorf("docker save: %w", err)
	}

	if _, err := msb.Image.Load(ctx, tar, tag); err != nil {
		return fmt.Errorf("loading the image into msb: %w", err)
	}

	a.report("made", "image "+tag)

	return nil
}

// checkImage runs the policy check on a built image.
func checkImage(ctx context.Context, tag string) error {
	out, err := command(ctx, "docker", "create", tag).Output()
	if err != nil {
		return fmt.Errorf("docker create: %w", err)
	}

	id := strings.TrimSpace(string(out))

	defer func() {
		if err := command(context.WithoutCancel(ctx), "docker", "rm", id).Run(); err != nil {
			slog.Warn("removing the check container", "container", id, "err", err)
		}
	}()

	tmp, err := os.MkdirTemp("", "sbx-check-")
	if err != nil {
		return fmt.Errorf("creating a temporary directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	// No trailing slash or -L on the source, so a link is copied as a link.
	dir := filepath.Join(tmp, "managed")
	if err := command(ctx, "docker", "cp", "-q", id+":"+claude.ManagedDir, dir).Run(); err != nil {
		return fmt.Errorf("docker cp %s: %w", claude.ManagedDir, err)
	}

	// os.DirFS follows a link at its root, which could point anywhere on the host.
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("reading the copied %s: %w", claude.ManagedDir, err)
	}

	if !info.IsDir() {
		return fmt.Errorf("image %s: %w: %s must be a real directory", tag, policy.ErrPolicy, claude.ManagedDir)
	}

	env, err := imageEnv(ctx, tag)
	if err != nil {
		return err
	}

	if err := errors.Join(policy.CheckManaged(os.DirFS(dir)), policy.CheckImageEnv(env)); err != nil {
		return fmt.Errorf("image %s: %w", tag, err)
	}

	return nil
}

// imageEnv returns the image's env as NAME=value entries.
func imageEnv(ctx context.Context, tag string) ([]string, error) {
	out, err := command(ctx, "docker", "image", "inspect", "--format", "{{json .Config.Env}}", tag).Output()
	if err != nil {
		return nil, fmt.Errorf("docker image inspect: %w", err)
	}

	var env []string
	if err := json.Unmarshal(out, &env); err != nil {
		return nil, fmt.Errorf("parsing the image env: %w", err)
	}

	return env, nil
}

// createSandbox creates the detached sandbox.
func (a *app) createSandbox(ctx context.Context, s *spec, image string) error {
	cfg := s.cfg

	env, err := cfg.EnvMap()
	if err != nil {
		return err
	}

	mounts := map[string]msb.MountConfig{}
	for _, v := range cfg.Volumes {
		mounts[v.Target] = msb.Mount.NamedWith(v.Name,
			msb.MountOptions{Nosuid: v.Nosuid, Nodev: v.Nodev},
			msb.NamedVolumeOptions{Mode: "ensure-exists", Kind: v.Kind, SizeMiB: v.SizeMiB})
	}

	network := &msb.NetworkConfig{
		DefaultEgress:  msb.PolicyAction(cfg.Network.DefaultEgress),
		DefaultIngress: msb.PolicyAction(cfg.Network.DefaultIngress),
		DisableStrict:  !cfg.Network.Strict,
	}

	if cfg.Network.InterceptTLS {
		network.TLS = &msb.TLSConfig{}
	}

	for _, r := range cfg.Network.Rules {
		network.Rules = append(network.Rules, msb.PolicyRule{
			Action: msb.PolicyAction(r.Action), Direction: msb.PolicyDirection(r.Direction),
			Destination: r.Destination, Protocol: msb.PolicyProtocol(r.Protocol), Port: r.Port,
		})
	}

	unlock, err := a.lock()
	if err != nil {
		return err
	}
	defer unlock()

	sb, err := msb.CreateSandbox(ctx, a.name,
		msb.WithImage(image),
		msb.WithPullPolicy(msb.PullPolicyNever), // the image is always loaded locally; never fetch a same-named one
		msb.WithCPUs(cfg.CPUs),
		msb.WithMemory(cfg.MemoryMiB),
		msb.WithRootDisk(msb.RootDisk.Managed(cfg.RootDiskMiB)),
		msb.WithUser(cfg.User),
		msb.WithWorkdir(cfg.Workdir),
		msb.WithShell(cfg.Shell),
		msb.WithSecurityProfile(msb.SecurityProfile(cfg.Security)),
		msb.WithEnv(env),
		msb.WithMounts(mounts),
		msb.WithNetwork(network),
		msb.WithDetached(),
	)
	if err != nil {
		return fmt.Errorf("creating sandbox %s: %w", a.name, err)
	}

	release(ctx, sb)

	return nil
}

// startSandbox connects to the sandbox, starting it if needed.
func (a *app) startSandbox(ctx context.Context) (*msb.Sandbox, error) {
	unlock, err := a.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	h, err := msb.GetSandbox(ctx, a.name)
	if err != nil {
		return nil, fmt.Errorf("finding sandbox %s: %w", a.name, err)
	}

	sb, err := h.ConnectOrStart(ctx, msb.WithConnectOrStartDetached())
	if err != nil {
		return nil, fmt.Errorf("starting sandbox %s: %w", a.name, err)
	}

	return sb, nil
}

// runningSandbox connects to the sandbox only if it is running: an exec into a stopped one would start it, then stop it again on exit.
func (a *app) runningSandbox(ctx context.Context) (*msb.Sandbox, *msb.SandboxHandle, error) {
	h, err := msb.GetSandbox(ctx, a.name)
	if err != nil {
		return nil, nil, fmt.Errorf("finding sandbox %s: %w", a.name, err)
	}

	if h.Status() != msb.SandboxStatusRunning {
		return nil, nil, fmt.Errorf("%w: %s is %s", errNotRunning, a.name, h.Status())
	}

	sb, err := h.Connect(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to sandbox %s: %w", a.name, err)
	}

	return sb, h, nil
}

// release detaches from the sandbox, leaving it running.
func release(ctx context.Context, sb *msb.Sandbox) {
	if err := sb.Detach(context.WithoutCancel(ctx)); err != nil {
		slog.Warn("releasing the sandbox handle", "err", err)
	}
}

// guest runs one argv command in the sandbox, as node in its home or as root in /.
func guest(ctx context.Context, sb *msb.Sandbox, user, cmd string, args ...string) (*msb.ExecOutput, error) {
	cwd := nodeHome
	if user == "root" {
		cwd = "/"
	}

	out, err := sb.Exec(ctx, cmd, args, msb.WithExecUser(user), msb.WithExecCwd(cwd))
	if err != nil {
		return nil, fmt.Errorf("running %s in the sandbox: %w", cmd, err)
	}

	return out, nil
}

// ownMounts starts the sandbox if needed and gives node the spec's mount roots.
func (a *app) ownMounts(ctx context.Context, s *spec) ([]string, error) {
	sb, err := a.startSandbox(ctx)
	if err != nil {
		return nil, err
	}

	defer release(ctx, sb)

	targets := make([]string, 0, len(s.cfg.Volumes))
	for _, v := range s.cfg.Volumes {
		targets = append(targets, v.Target)
	}

	return chownMounts(ctx, sb, targets)
}

// chownMounts gives node the mount roots.
func chownMounts(ctx context.Context, sb *msb.Sandbox, targets []string) ([]string, error) {
	var changed []string

	for _, target := range targets {
		out, err := guest(ctx, sb, "root", "stat", "-c", "%u:%g", target)
		if err != nil {
			return changed, err
		}

		if !out.Success() {
			return changed, fmt.Errorf("stat %s: %s", target, strings.TrimSpace(out.Stderr()))
		}

		if strings.TrimSpace(out.Stdout()) == "1000:1000" {
			continue
		}

		out, err = guest(ctx, sb, "root", "chown", "1000:1000", target)
		if err != nil {
			return changed, err
		}

		if !out.Success() {
			return changed, fmt.Errorf("chown %s: %s", target, strings.TrimSpace(out.Stderr()))
		}

		changed = append(changed, target)
	}

	return changed, nil
}

// liveSpec reads the sandbox's live config.
func liveSpec(ctx context.Context, h *msb.SandboxHandle) (policy.Spec, error) {
	return policy.FromConfigJSON([]byte(h.ConfigJSON()), func(name string) (string, error) {
		v, err := msb.GetVolume(ctx, name)
		if err != nil {
			return "", fmt.Errorf("finding the volume: %w", err)
		}

		return string(v.Kind()), nil
	})
}

// backgroundSessions lists the background sessions, running claude as node in its home: never in a repo, whose config it would load.
func backgroundSessions(ctx context.Context, sb *msb.Sandbox) ([]agent.Session, error) {
	out, err := guest(ctx, sb, "node", "claude", "agents", "--json")
	if err != nil {
		return nil, err
	}

	if !out.Success() {
		return nil, fmt.Errorf("claude agents: %q", strings.TrimSpace(out.Stderr()))
	}

	return agent.ParseSessions(out.StdoutBytes())
}
