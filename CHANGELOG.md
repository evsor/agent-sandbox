# Changelog

This file lists the notable changes to this project. It uses the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format, and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `sbx config` writes the example config to `~/.config/agent-sandbox/`, asking for your git name and email, the sandbox name, the CPUs and the memory. It never changes a file that exists. `--config-dir` or `SBX_CONFIG_DIR` chooses another dir.

### Changed

- `sbx status` says whether your config differs from the one the last rebuild applied, and names the files.
- `sbx init`, `sbx rebuild` and `sbx status` read the config from `~/.config/agent-sandbox/`, so they no longer need an agent-sandbox checkout. The repo's `config/` is now `example/`, the default that `sbx config` copies.
- `sbx rebuild` builds your config as it is, shows the changes since the last rebuild, and after verifying keeps a copy in `~/.local/state/agent-sandbox/applied/`.
- The image tag is a hash of the Dockerfile, `.dockerignore` and `image/`, not a git commit. `sbx rebuild` reuses an image that msb already has under that tag.
- The SSH config runs `sbx` from wherever it is installed, in a path without whitespace. Run `sbx init` again after you move it.
- To migrate an existing setup: run `sbx config`, copy your git identity and your other edits from the checkout's `config/` into `~/.config/agent-sandbox/`, then run `sbx rebuild`.

### Removed

- The `<sha>` argument of `sbx rebuild`, and the need to run `sbx` from an agent-sandbox checkout.

## [0.3.1] - 2026-11-07

### Added

- `passthrough` in a `[[secrets]]` entry of `sandbox.toml` lists the hosts that can receive the placeholder. Each secret must include `api.anthropic.com`, or the gateway blocks the conversation.
- `sandbox.toml` tells how secrets work and how to add one.

### Changed

- The managed settings permit auto mode. The ask and deny rules still apply in it.

### Fixed

- Claude Code sessions no longer stop when a secret's placeholder is in the conversation.

## [0.3.0] - 2026-11-07

### Added

- `sbx clone [<owner/name>...]` clones GitHub repos into `/workspace` in the sandbox.

## [0.2.0] - 2026-11-05

### Added

- `sbx rebuild [<sha>]` builds the image from `origin/main` and creates the sandbox again. It shows the changes since the last rebuild and keeps the volumes.

## [0.1.0] - 2026-11-04

First release.

### Added

- `sbx init` checks the host, builds the image from `config/`, writes the SSH files, creates and starts the sandbox, and verifies it. You can run it again safely.
- `sbx status`, `sbx stop` and `sbx verify`. If a boundary check fails, `sbx verify` stops the sandbox.
- `sbx connect` is the SSH `ProxyCommand` for `ssh` and VS Code Remote-SSH.
- `sbx rotate` updates each secret from its host variable.
- `sbx ship` fetches an agent branch from the sandbox to the host.
