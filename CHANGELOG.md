# Changelog

This file lists the notable changes to this project. It uses the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format, and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-11-25

### Added

- `sbx init` writes the example config, now part of `sbx`, into the user config dir `~/.config/agent-sandbox/` where a file is missing. It never changes a file that exists. When it writes `image/etc/gitconfig`, it asks for the git name and email for commits in the sandbox, offering the host's; `--git-name` and `--git-email` skip the question.
- `--config-dir` and `SBX_CONFIG_DIR` choose the user config dir. `sbx init` records it for the other commands. Point it at the `config/` directory of a checkout to keep the config in git.

### Changed

- **Existing users:** run `sbx init`, then copy your edits from your checkout's `config/` into `~/.config/agent-sandbox/` and run `sbx rebuild`.
- `sbx init`, `sbx rebuild` and `sbx status` read only the user config dir and no longer need an agent-sandbox checkout. The image is built from that dir and tagged with a hash of its build files instead of a commit.
- `sbx rebuild` takes no argument and builds the user config dir as it is. It shows the allowlist and secret changes since the last verified create, whose `sandbox.toml` it keeps in `~/.local/state/agent-sandbox/applied.toml`.
- `sbx status` reports a pending rebuild when the user config dir has changed since the last verified create.
- The SSH config runs `sbx` from where it is installed, so it can be anywhere on `PATH`. Run `sbx init` again after you move it.

### Removed

- `sbx rebuild <sha>` and the check that the operator clone is clean and on `origin/main`.

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
