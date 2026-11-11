# Changelog

This file lists the notable changes to this project. It uses the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format, and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
