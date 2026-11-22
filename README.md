# agent-sandbox

[![CI](https://img.shields.io/github/actions/workflow/status/evsor/agent-sandbox/ci.yml?branch=main&label=CI)](https://github.com/evsor/agent-sandbox/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/evsor/agent-sandbox)](https://github.com/evsor/agent-sandbox/releases/latest)
[![Go](https://img.shields.io/github/go-mod/go-version/evsor/agent-sandbox)](go.mod)
[![License](https://img.shields.io/github/license/evsor/agent-sandbox)](LICENSE)

`sbx` is a helper CLI tool to run alongside [microsandbox](https://github.com/superradcompany/microsandbox) (msb).
It creates and manages a long-lived local development environment for AI agents, abstracts away and centralizes configuration management, sets a security baseline, establishes a policy framework and checks the running sandbox against it.

## Features

- **One-command setup**: Get a verified, running sandbox on a new host with one command.

- **Sandbox as code**: Keep the sandbox, the agent rules and the network allowlist in files.

- **Enforced security baseline**: Refuses a config or an image that violates the baseline. Stops a running sandbox that fails the check.

- **Editor-ready workspace**: Open the sandbox in VS Code like any remote host.

- **Safe code flow**: Clone your repos into the sandbox and ship agent work to GitHub as PRs. The sandbox doesn't need push credentials.

## Prerequisites

- msb, docker, git, ssh

## Installation

Download the binary from releases to any directory on your `PATH`. The SSH config runs `sbx` from where `sbx init` ran it, so run `sbx init` again after you move it.

## Getting started

1. Export `GITHUB_PAT`, a read-only GitHub token, in the shell that you use for `sbx`.
2. Run `sbx init`. It writes the example config to `~/.config/agent-sandbox/` and asks for the git name and email for commits in the sandbox (Enter takes your host's). Then it checks the host, builds the image, runs the policy check, starts the sandbox and verifies it. It never changes a file in `~/.config/agent-sandbox/` that exists, so you can rerun it safely.
3. Add the `Include` line that `sbx init` prints to the top of `~/.ssh/config`, before any `Host` line:

   ```text
   Include ~/.local/state/agent-sandbox/ssh/config
   ```

4. (Optional)In VS Code, install Remote-SSH. Add these user settings. Keep `remote.SSH.localServerDownload` at `auto`.

   ```json
   "remote.autoForwardPorts": false,
   "remote.SSH.defaultExtensions": ["Anthropic.claude-code"]
   ```

5. Run `sbx clone <owner/name>...` to clone your repos into `/workspace`. Or clone them from inside the sandbox
6. Connect VS Code to `claude-sandbox`. Open a folder in `/workspace`.

To keep the config in git, set `SBX_CONFIG_DIR` (or pass `--config-dir`) to the `config/` directory of a checkout when you run `sbx init`. `sbx` remembers it.

## Daily use

### Editor(VS Code) flow

1. Connect: Open VS Code on `claude-sandbox`. A stopped sandbox starts on connection.

2. To add a repo, run `sbx clone` in a host checkout of it, or `sbx clone <owner/name>` from any directory.

3. To ship work, run `sbx ship` or `sbx ship <repo> <branch>`.

### Recreate the sandbox

`sbx rebuild` builds the image from `~/.config/agent-sandbox/` as it is and recreates the sandbox.
The volumes are kept untouched. Before it starts, it shows the allowlist and secret changes since the last verified create and the background sessions that it will stop. If the result is `VERIFY FAILED`, fix the config and run `sbx rebuild` again. The `sandbox.toml` of the last verified create is `~/.local/state/agent-sandbox/applied.toml`.

## Changing the sandbox

Edit the files in `~/.config/agent-sandbox/`, then run `sbx rebuild`. `sbx status` shows a pending rebuild while they differ from the last verified create.

| To change | Edit, in `~/.config/agent-sandbox/` |
|---|---|
| Packages | `Dockerfile` |
| Claude Code rules | `managed-settings.json` and `CLAUDE.md` in `image/etc/claude-code/` |
| Git name, email and defaults | `image/etc/gitconfig` |
| CPUs, memory, allowed hosts, secrets | `sandbox.toml` |

A new `sbx` release can bring a newer example config. `sbx init` writes only the files that are missing, so copy the changes you want from `config/` in this repo by hand. The changelog lists them.

`sbx` checks a security baseline that a config change cannot override:

- the VM settings
- the network denies
- port 443 only
- the volumes
- no bypass mode and subscription login only

To change the above, you need a new `sbx` release.

### To allow a host

1. Add the new host to `allow_domains` with a comment.
2. `.example.com` also matches subdomains.
3. Use `allow_ips` only for a service with no usable name.

### Secrets

A secret's value stays on the host, it never enters the sandbox. The sandbox can only access a placeholder, and msb's network gateway swaps the placeholder to the real value in `header_fields` headers of requests to the `allow` hosts. It blocks the placeholder everywhere else.
Because of that **each secret must have `passthrough = ["api.anthropic.com"]`.** as the placeholder can appear in conversations, and Claude Code sends the full conversation with each request. If this happens, the gateway blocks these requests and the session stops. To avoid that, we need the `passthrough` setting.

### To add a secret:

1. Copy the `GITHUB_PAT` block in `~/.config/agent-sandbox/sandbox.toml`. Change `name` (the host variable), `allow`, `placeholder` (no `$`) and `header_fields`.
2. Add the hosts to `allow_domains`.
3. If a tool reads its token from a variable, add an `env` entry with the placeholder, as for `GH_TOKEN`.
4. Export the variable on the host. Then run `sbx rebuild`.

## Troubleshooting

If a tool shows NXDOMAIN or "could not resolve host", the host is not on the allowlist. Add it to `allow_domains` in `~/.config/agent-sandbox/sandbox.toml` and run `sbx rebuild`.

If a Claude session stops answering after some minutes of retries, the gateway probably blocks a placeholder on its way to the Claude API. Search msb's runtime log on the host:

If it finds a match, add the missing `passthrough` in `~/.config/agent-sandbox/sandbox.toml` and run `sbx rebuild`. After the rebuild, the session works again.

The SSH config sets keepalives that end a dead connection. If SSH stops responding, make sure that the `Include` line is at the top of `~/.ssh/config`. Then run `sbx init` to write the SSH config again.

A rebuild or restart stops background sessions. `claude agents` lists them. `claude respawn <id>` or `claude respawn --all` starts them again.

## Incident response

If you think that the sandbox or an agent is compromised:

1. Run `sbx stop`.
2. Run `/logout` in the sandbox. Then revoke the session in your claude.ai settings.
3. Revoke the GitHub token.
4. Before you run `sbx rebuild`, examine the files in `~/.config/agent-sandbox/`. The `sandbox.toml` of the last verified create is `~/.local/state/agent-sandbox/applied.toml`. Before you install a release, examine its changes in `cmd/` and `internal/`.

