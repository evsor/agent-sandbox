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

Download the binary from releases and put it anywhere on your `PATH`, in a path without whitespace. The SSH config that `sbx init` writes runs `sbx` from where it is, so run `sbx init` again after you move it.

## Getting started

1. Run `sbx config`. It writes the example config to `~/.config/agent-sandbox/` and asks for a few values, each with its default: press Enter to take it. It asks for the config dir, your git name and email, the sandbox name, the CPUs and the memory. Use your GitHub noreply address as the email (`12345+you@users.noreply.github.com`). Without a git name and email, git refuses commits inside the sandbox until you add them below `[user]` in `image/etc/gitconfig`.
2. Look through the files in `~/.config/agent-sandbox/` and change what you need (see [Changing the sandbox](#changing-the-sandbox)).
3. Export intended secrets in the shell that you use for `sbx`
4. Run `sbx init`. It checks the host, builds the image, runs the policy check, starts the sandbox and verifies it. It's idempotent, so you can rerun it safely
5. Add the `Include` line that `sbx init` prints to the top of `~/.ssh/config`, before any `Host` line:

   ```text
   Include ~/.local/state/agent-sandbox/ssh/config
   ```

6. (Optional)In VS Code, install Remote-SSH. Add these user settings. Keep `remote.SSH.localServerDownload` at `auto`.

   ```json
   "remote.autoForwardPorts": false,
   "remote.SSH.defaultExtensions": ["Anthropic.claude-code"]
   ```

7. Run `sbx clone <owner/name>...` to clone your repos into `/workspace`. Or clone them from inside the sandbox
8. Connect VS Code to `claude-sandbox` (or the sandbox name you chose). Open a folder in `/workspace`.

## Daily use

### Editor(VS Code) flow

1. Connect: Open VS Code on `claude-sandbox`. A stopped sandbox starts on connection.

2. To add a repo, run `sbx clone` in a host checkout of it, or `sbx clone <owner/name>` from any directory.

3. To ship work, run `sbx ship` or `sbx ship <repo> <branch>`.

### Recreate the sandbox

`sbx rebuild` builds the image from `~/.config/agent-sandbox/` and recreates the sandbox. The volumes are kept untouched. Before it starts, it shows the allowlist and secret changes since the last rebuild, names the other files that changed, and lists the background sessions that it will stop.
After the sandbox passes verification, `sbx rebuild` keeps a copy of the config in `~/.local/state/agent-sandbox/applied/`. `sbx status` tells you whether your config differs from it. If the result is `VERIFY FAILED`, copy `applied/` back to `~/.config/agent-sandbox/` and run `sbx rebuild`.

## Changing the sandbox

Edit the files in `~/.config/agent-sandbox/`, then run `sbx rebuild`.

| To change | Edit |
|---|---|
| Packages | `Dockerfile` |
| Claude Code rules | `managed-settings.json` and `CLAUDE.md` in `image/etc/claude-code/` |
| Git defaults and identity | `image/etc/gitconfig` |
| CPUs, memory, allowed hosts, secrets | `sandbox.toml` |

[`example/`](example/) in this repo is the default config that `sbx config` copies. `sbx config` never changes a file that exists. When a release ships a newer example, for example a new Claude Code version, the [changelog](CHANGELOG.md) says so, and you copy the change into your config by hand.

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

1. Copy the `GITHUB_PAT` block in `sandbox.toml`. Change `name` (the host variable), `allow`, `placeholder` (no `$`) and `header_fields`.
2. Add the hosts to `allow_domains`.
3. If a tool reads its token from a variable, add an `env` entry with the placeholder, as for `GH_TOKEN`.
4. Export the variable on the host. Then run `sbx rebuild`.

## Troubleshooting

If a tool shows NXDOMAIN or "could not resolve host", the host is not on the allowlist. Add it to `allow_domains` in `~/.config/agent-sandbox/sandbox.toml` and run `sbx rebuild`.

If a Claude session stops answering after some minutes of retries, the gateway probably blocks a placeholder on its way to the Claude API. Search msb's runtime log on the host:

If it finds a match, add the missing `passthrough` and run `sbx rebuild`. After the rebuild, the session works again.

The SSH config sets keepalives that end a dead connection. If SSH stops responding, make sure that the `Include` line is at the top of `~/.ssh/config`. Then run `sbx init` to write the SSH config again.

A rebuild or restart stops background sessions. `claude agents` lists them. `claude respawn <id>` or `claude respawn --all` starts them again.

## Incident response

If you think that the sandbox or an agent is compromised:

1. Run `sbx stop`.
2. Run `/logout` in the sandbox. Then revoke the session in your claude.ai settings.
3. Revoke the GitHub token.
4. Before you rebuild, compare `~/.config/agent-sandbox/` with the last applied copy in `~/.local/state/agent-sandbox/applied/` (`sbx status` names the files that differ). Before you install a new `sbx` release, examine the recent PRs and commits on `main`, especially in `cmd/` and `internal/`.

